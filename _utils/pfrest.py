"""
Minimal client for pfSense REST API v2 (pfSense-pkg-RESTAPI, "pfrest"), called locally by the minion.

Objects are identified by their index in config.xml, which changes on every insertion or deletion:
never cache an id, resolve it from a natural key right before writing (find_one) and check the object
after writing (write_checked). See docs/migration/plan.md (lot 2) and docs/rd/03-verrous.md (V1, V2, V3).
"""

import contextlib
import fcntl
import logging
import re
from typing import Any, Callable, Iterator

import requests

logger = logging.getLogger(__name__)

API_KEY_FILE = "/usr/local/etc/salt-pfsense/api.key"
LOCK_FILE = "/var/run/salt-pfsense.lock"
BASE_URL = "https://127.0.0.1"
TIMEOUT = 60

# Apply endpoint of each domain (models without always_apply)
APPLY_ENDPOINTS = {
    "dhcp": "services/dhcp_server/apply",
    "firewall": "firewall/apply",
    "interface": "interface/apply",
    "routing": "routing/apply",
    "wireguard": "vpn/wireguard/apply",
}


class PfrestError(Exception):
    def __init__(self, code: int, response_id: str, message: str) -> None:
        super().__init__("pfrest {0} {1}: {2}".format(code, response_id, message))
        self.code = code
        self.response_id = response_id
        self.message = message


class PfrestConflict(PfrestError):
    """config.xml was written by someone else since the run started (V2)."""


def read_api_key(path: str = API_KEY_FILE) -> str:
    with open(path) as handle:
        key = handle.read().strip()
    if not key:
        raise PfrestError(0, "SALT_PFSENSE_EMPTY_API_KEY", "API key file {0} is empty".format(path))
    return key


class PfrestClient:
    def __init__(
        self,
        base_url: str = BASE_URL,
        api_key: str | None = None,
        verify: bool | str = False,
        dry_run: bool = False,
        session: Any = None,
        key_reader: Callable[[], str] = read_api_key,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/api/v2/"
        self._api_key = api_key if api_key is not None else key_reader()
        self.verify = verify
        self.dry_run = dry_run
        self.session = session if session is not None else requests.Session()
        self.expected_revision: Any = None
        self.writes = 0
        if verify is False:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def __repr__(self) -> str:
        return "PfrestClient({0!r}, dry_run={1})".format(self.base_url, self.dry_run)

    # transport
    # =========================================================================

    def _request(self, method: str, endpoint: str, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        headers = {"X-API-Key": self._api_key, "Accept": "application/json"}
        response = self.session.request(
            method,
            self.base_url + endpoint,
            params=params,
            json=body,
            headers=headers,
            verify=self.verify,
            timeout=TIMEOUT,
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if response.status_code >= 400 or payload.get("status") not in (None, "ok"):
            # Never include the request body: it may hold secrets
            raise PfrestError(
                response.status_code,
                payload.get("response_id", "UNKNOWN"),
                payload.get("message", "unexpected response"),
            )
        return payload.get("data")

    def get(self, endpoint: str, **params: Any) -> Any:
        return self._request("GET", endpoint, params=params or None)

    def post(self, endpoint: str, body: dict[str, Any], apply: bool = False) -> Any:
        return self._write("POST", endpoint, dict(body, apply=apply))

    def patch(self, endpoint: str, body: dict[str, Any], apply: bool = False) -> Any:
        return self._write("PATCH", endpoint, dict(body, apply=apply))

    def delete(self, endpoint: str, id: Any, parent_id: Any = None, apply: bool = False) -> Any:
        params: dict[str, Any] = {"id": id, "apply": apply}
        if parent_id is not None:
            params["parent_id"] = parent_id
        if self.dry_run:
            params["dry_run"] = True
        self._check_revision()
        data = self._request("DELETE", endpoint, params=params)
        self.writes += 1
        self._own_write()
        return data

    def _write(self, method: str, endpoint: str, body: dict[str, Any]) -> Any:
        if self.dry_run:
            body["dry_run"] = True
        self._check_revision()
        data = self._request(method, endpoint, body=body)
        self.writes += 1
        self._own_write()
        return data

    def download(self, endpoint: str, body: dict[str, Any]) -> tuple[str | None, bytes]:
        """POST an action returning a file (binary content); return (filename, content)."""
        headers = {"X-API-Key": self._api_key, "Accept": "application/octet-stream"}
        response = self.session.request(
            "POST", self.base_url + endpoint, json=body, headers=headers, verify=self.verify, timeout=TIMEOUT
        )
        if response.status_code >= 400:
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            raise PfrestError(
                response.status_code, payload.get("response_id", "UNKNOWN"), payload.get("message", "download failed")
            )
        match = re.search(r'filename="?([^";]+)"?', response.headers.get("Content-Disposition", ""))
        return (match.group(1) if match else None), response.content

    # apply (V3)
    # =========================================================================

    def apply(self, domain: str) -> Any:
        """Apply the pending changes of a domain synchronously; no-op in dry-run."""
        if self.dry_run:
            return None
        return self._request("POST", APPLY_ENDPOINTS[domain], body={"async": False})

    def pending(self, domain: str) -> bool:
        """True when the domain has pending changes (not reliable for firewall rules, see V3)."""
        data = self._request("GET", APPLY_ENDPOINTS[domain])
        return not data.get("applied", True)

    # identity (V1)
    # =========================================================================

    def find(self, endpoint: str, parent_id: Any = None, **key: Any) -> list[dict[str, Any]]:
        """Objects of a plural endpoint whose fields equal key (filtered server side and checked again)."""
        params = dict(key)
        if parent_id is not None:
            params["parent_id"] = parent_id
        objects = self.get(endpoint, **params) or []
        return [obj for obj in objects if all(obj.get(field) == value for field, value in key.items())]

    def find_one(
        self, endpoint: str, parent_id: Any = None, allow_missing: bool = False, **key: Any
    ) -> dict[str, Any] | None:
        objects = self.find(endpoint, parent_id=parent_id, **key)
        if len(objects) > 1:
            raise PfrestError(
                0, "SALT_PFSENSE_AMBIGUOUS_KEY", "{0} objects match {1} on {2}".format(len(objects), key, endpoint)
            )
        if not objects:
            if allow_missing:
                return None
            raise PfrestError(0, "SALT_PFSENSE_NOT_FOUND", "no object matches {0} on {1}".format(key, endpoint))
        return objects[0]

    def write_checked(
        self,
        method: str,
        endpoint: str,
        list_endpoint: str,
        key: dict[str, Any],
        body: dict[str, Any] | None = None,
        parent_id: Any = None,
        apply: bool = False,
    ) -> dict[str, Any] | None:
        """
        Create (POST), update (PATCH) or delete (DELETE) the object identified by key, resolving its id
        right before the write and checking the natural key right after it.
        """
        body = dict(body or {})
        if parent_id is not None:
            body["parent_id"] = parent_id
        if method == "POST":
            self.post(endpoint, dict(body, **key), apply=apply)
        else:
            current = self.find_one(list_endpoint, parent_id=parent_id, **key)
            assert current is not None
            if method == "PATCH":
                self.patch(endpoint, dict(body, id=current["id"]), apply=apply)
            else:
                self.delete(endpoint, current["id"], parent_id=parent_id, apply=apply)
        if self.dry_run:
            return None
        found = self.find_one(list_endpoint, parent_id=parent_id, allow_missing=True, **key)
        if method == "DELETE":
            if found is not None:
                raise PfrestError(0, "SALT_PFSENSE_CHECK_FAILED", "{0} still present on {1}".format(key, endpoint))
            return None
        if found is None:
            raise PfrestError(0, "SALT_PFSENSE_CHECK_FAILED", "{0} missing after write on {1}".format(key, endpoint))
        return found

    # concurrency (V2)
    # =========================================================================

    def revision(self) -> Any:
        """Latest config.xml revision time from the configuration history."""
        revisions = self.get("diagnostics/config_history/revisions") or []
        return max((r.get("time") for r in revisions), default=None)

    def _check_revision(self) -> None:
        if self.expected_revision is None:
            return
        current = self.revision()
        if current != self.expected_revision:
            raise PfrestConflict(
                0,
                "SALT_PFSENSE_CONFLICT",
                "config.xml changed during the run ({0} != {1})".format(current, self.expected_revision),
            )

    def _own_write(self) -> None:
        if self.expected_revision is not None and not self.dry_run:
            self.expected_revision = self.revision()


@contextlib.contextmanager
def config_lock(client: PfrestClient, path: str | None = None) -> Iterator[PfrestClient]:
    """
    Serialize the read -> write -> apply sequences of concurrent Salt runs on the minion, and detect
    writes made by others (WebGUI, HA sync) in between.
    """
    with open(path or LOCK_FILE, "a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        client.expected_revision = client.revision()
        try:
            yield client
        finally:
            client.expected_revision = None
            fcntl.flock(handle, fcntl.LOCK_UN)
