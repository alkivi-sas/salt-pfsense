"""pfrest implementation of pfsense_alias (firewall/alias, natural key: name)."""

from typing import Any

from salt.exceptions import CommandExecutionError, SaltInvocationError

import pfrest

ONE = "firewall/alias"
MANY = "firewall/aliases"
TYPES = ("host", "network", "port")


def _legacy(obj: dict[str, Any]) -> dict[str, Any]:
    """Same shape as the FauxAPI backend: space separated address plus an addresses list."""
    addresses = [str(a) for a in obj.get("address") or []]
    return {
        "name": obj["name"],
        "type": obj.get("type"),
        "descr": obj.get("descr", ""),
        "address": " ".join(addresses),
        "addresses": addresses,
        "detail": "||".join(obj.get("detail") or []),
        "url": "",
        "updatefreq": "",
    }


def list_aliases(api: pfrest.PfrestClient) -> dict[str, dict[str, Any]]:
    return {obj["name"]: _legacy(obj) for obj in api.get(MANY) or []}


def set_target(
    api: pfrest.PfrestClient,
    alias: str,
    targets: list[str],
    type: str | None = None,
    descr: str | None = None,
    detail: str | None = None,
    url: str | None = None,
    updatefreq: str | None = None,
) -> bool:
    if url or updatefreq:
        raise CommandExecutionError("URL table aliases are not covered by pfrest (alias {0})".format(alias))
    body: dict[str, Any] = {"address": targets}
    if descr:
        body["descr"] = descr
    if detail:
        body["detail"] = detail.split("||")

    current = api.find_one(MANY, allow_missing=True, name=alias)
    if current is None:
        if type not in TYPES:
            raise SaltInvocationError("type must be one of {0} on the pfrest backend".format(", ".join(TYPES)))
        api.write_checked("POST", ONE, MANY, {"name": alias}, body=dict(body, type=type))
        return True

    if type and type != current["type"]:
        raise CommandExecutionError("You ask for type {0} but already present as {1}".format(type, current["type"]))
    unchanged = set(map(str, current.get("address") or [])) == set(targets)
    if descr is not None and current.get("descr", "") != descr:
        unchanged = False
    if unchanged:
        return True
    api.write_checked("PATCH", ONE, MANY, {"name": alias}, body=body)
    return True


def rm_alias(api: pfrest.PfrestClient, alias: str) -> bool:
    if api.find_one(MANY, allow_missing=True, name=alias) is not None:
        api.write_checked("DELETE", ONE, MANY, {"name": alias})
    return True
