"""
Lifecycle of pfSense-pkg-RESTAPI on the firewall: install the pinned version, bootstrap the dedicated
API user and key without any admin password, manage the package settings. See docs/migration/restapi.md.

The API key comes from the pillar (pfsense:restapi:api_key, 64 hexadecimal characters) and is never
passed as an argument, logged or returned.
"""

import json
import logging
import os
from typing import Any

import pfrest
import pfrest_lifecycle as lifecycle
import pfsense_local
from salt.exceptions import CommandExecutionError

logger = logging.getLogger(__name__)

__virtualname__ = "pfsense_restapi"

HELPER = "/opt/helpers/restapi_bootstrap.php"
PILLAR_KEY = "pfsense:restapi:api_key"
PILLAR_SETTINGS = "pfsense:restapi:settings"
PILLAR_ACCESS_LIST = "pfsense:restapi:access_list"
DEFAULT_ACCESS_LIST = [{"network": "127.0.0.1/32"}]


def __virtual__() -> Any:
    if os.path.isfile("/etc/pf.os"):
        return __virtualname__
    return (False, "pfsense_restapi: not a pfSense system")


def _base_edition() -> tuple[str, str]:
    with open("/etc/version") as handle:
        return lifecycle.parse_version(handle.read())


def installed_version() -> str:
    """Installed package version (e.g. 2.10_2), empty string when absent."""
    result = __salt__["cmd.run_all"](["pkg", "query", "%v", lifecycle.PACKAGE], python_shell=False, ignore_retcode=True)
    return result["stdout"].strip() if result["retcode"] == 0 else ""


def install(version: str | None = None, test: bool = False) -> dict[str, Any]:
    """Install the pinned pfrest release, or move to it with pfsense-restapi revert. Return the changes."""
    tag = version or lifecycle.PFREST_VERSION
    base, edition = _base_edition()
    if not lifecycle.is_supported(base, tag):
        raise CommandExecutionError("pfrest {0} has no package for pfSense {1} {2}".format(tag, edition, base))
    current, wanted = installed_version(), lifecycle.package_version(tag)
    if current == wanted:
        return {}
    changes = {"old": current, "new": wanted}
    if test:
        return changes
    cmd = ["pfsense-restapi", "revert", tag] if current else lifecycle.install_command(base, edition, tag)
    result = __salt__["cmd.run_all"](cmd, python_shell=False)
    if result["retcode"] != 0:
        raise CommandExecutionError("unable to install {0} {1}: {2}".format(lifecycle.PACKAGE, tag, result["stderr"]))
    return changes


def _api_key() -> str:
    key = __salt__["pillar.get"](PILLAR_KEY, "")
    if len(key) != lifecycle.KEY_LENGTH_BYTES * 2:
        raise CommandExecutionError(
            "pillar {0} must hold {1} hexadecimal characters".format(PILLAR_KEY, lifecycle.KEY_LENGTH_BYTES * 2)
        )
    return key


def _key_file_matches(key: str, path: str) -> bool:
    try:
        return pfrest.read_api_key(path) == key
    except (OSError, pfrest.PfrestError):
        return False


def _write_key_file(key: str, path: str | None = None) -> bool:
    path = path or pfrest.API_KEY_FILE
    if _key_file_matches(key, path):
        return False
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(key + "\n")
    return True


def bootstrap(test: bool = False) -> dict[str, Any]:
    """Create the API user, group, key hash and enable KeyAuth (V7). Return the changes, without secrets."""
    key = _api_key()
    changes: dict[str, Any] = {}
    if test:
        if _key_file_matches(key, pfrest.API_KEY_FILE):
            try:
                status()
                return {}
            except pfrest.PfrestError:
                pass
        return {"bootstrap": "would run"}
    if _write_key_file(key):
        changes["key_file"] = "updated"
    request = {
        "username": lifecycle.API_USER,
        "group": lifecycle.API_GROUP,
        "privileges": lifecycle.privileges(),
        "key_hash": lifecycle.key_hash(key),
        "hash_algo": lifecycle.KEY_HASH_ALGO,
        "length_bytes": lifecycle.KEY_LENGTH_BYTES,
        "descr": lifecycle.KEY_DESCR,
    }
    result = __salt__["cmd.run_all"](
        ["php", HELPER], stdin=json.dumps(request), python_shell=False, output_loglevel="quiet", ignore_retcode=True
    )
    if result["retcode"] != 0:
        raise CommandExecutionError("REST API bootstrap failed: {0}".format(result["stderr"]))
    if json.loads(result["stdout"]).get("changed"):
        changes["config"] = "user, group, key and auth methods updated"
    return changes


def client(test: bool = False) -> pfrest.PfrestClient:
    """Client on the local WebGUI port, dry_run in test mode."""
    return pfrest.PfrestClient(base_url=pfsense_local.webgui_base_url(pfsense_local.read_config()), dry_run=test)


def status() -> dict[str, Any]:
    """Check that the API answers with the managed key."""
    return {"version": client().get("system/version")}


def _differs(current: Any, wanted: Any) -> bool:
    if isinstance(wanted, list) and isinstance(current, list):
        return sorted(map(str, current)) != sorted(map(str, wanted))
    return current != wanted


def configure(settings: dict[str, Any] | None = None, test: bool = False) -> dict[str, Any]:
    """Apply DEFAULT_SETTINGS (merged with the pillar or the given settings) and the access list."""
    wanted = dict(lifecycle.DEFAULT_SETTINGS)
    wanted.update(__salt__["pillar.get"](PILLAR_SETTINGS, {}))
    wanted.update(settings or {})
    api = client(test)
    current = api.get("system/restapi/settings") or {}
    patch = {name: value for name, value in wanted.items() if _differs(current.get(name), value)}
    changes: dict[str, Any] = {}
    if patch:
        api.patch("system/restapi/settings", patch)
        changes["settings"] = {name: {"old": current.get(name), "new": value} for name, value in patch.items()}

    entries = api.get("system/restapi/access_list") or []
    for entry in __salt__["pillar.get"](PILLAR_ACCESS_LIST, DEFAULT_ACCESS_LIST):
        if any(e.get("network") == entry["network"] for e in entries):
            continue
        body = {"type": "allow", "weight": 1, "users": [lifecycle.API_USER], "descr": lifecycle.KEY_DESCR}
        body.update(entry)
        api.post("system/restapi/access_list/entry", body)
        changes.setdefault("access_list", []).append(entry["network"])
    return changes
