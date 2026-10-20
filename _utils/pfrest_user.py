"""
pfrest implementation of the pfsense_user writes (user, user/group, natural key: name).

Reads stay on the local config.xml (exact FauxAPI shapes, hashes not masked). pfrest creates and
updates the FreeBSD account itself (local_user_set), so no Salt user.* call is needed. The pillar
holds bcrypt hashes, which pfrest can not take: they go through a local helper (user_set_fields.php).
"""

import base64
import secrets
from typing import Any, Callable

from salt.exceptions import CommandExecutionError

import pfrest

ONE = "user"
MANY = "users"
GROUP = "user/group"
GROUPS = "user/groups"

# legacy attribute -> config.xml field set by the helper (not modelled by pfrest)
HELPER_FIELDS = {"password": "bcrypt-hash", "dashboardcolumns": "dashboardcolumns", "webguicss": "webguicss"}
API_FIELDS = ("descr", "expires", "authorizedkeys", "ipsecpsk", "disabled", "priv")

Helper = Callable[[str, dict[str, Any]], bool]


def _api_body(attributes: dict[str, Any]) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for name, value in attributes.items():
        if name in HELPER_FIELDS:
            continue
        if name not in API_FIELDS:
            raise CommandExecutionError("unsupported attribute type", name)
        if name == "disabled":
            body[name] = value is True
        elif name == "authorizedkeys":
            # config.xml (and the states) hold base64, pfrest takes the clear keys
            body[name] = base64.b64decode(value).decode("utf-8") if value else ""
        elif name == "priv":
            body[name] = list(value or [])
        else:
            body[name] = value
    return body


def _helper_fields(attributes: dict[str, Any]) -> dict[str, Any]:
    return {HELPER_FIELDS[name]: value for name, value in attributes.items() if name in HELPER_FIELDS}


def _public(username: str, attributes: dict[str, Any]) -> dict[str, Any]:
    """Changes reported to the state: never the password hash."""
    return dict({k: v for k, v in attributes.items() if k != "password"}, name=username)


def add_user(api: pfrest.PfrestClient, helper: Helper, username: str, attributes: dict[str, Any]) -> dict[str, Any]:
    # pfrest requires a password: a random one, replaced by the pillar hash when given
    body = dict(_api_body(attributes), name=username, password=secrets.token_hex(32))
    api.write_checked("POST", ONE, MANY, {"name": username}, body=body)
    fields = _helper_fields(attributes)
    if fields and not api.dry_run:
        helper(username, fields)
    return _public(username, attributes)


def manage_user(api: pfrest.PfrestClient, helper: Helper, username: str, attributes: dict[str, Any]) -> dict[str, Any]:
    body = _api_body(attributes)
    if body:
        api.write_checked("PATCH", ONE, MANY, {"name": username}, body=body)
    fields = _helper_fields(attributes)
    if fields and not api.dry_run:
        helper(username, fields)
    return _public(username, attributes)


def set_certs(api: pfrest.PfrestClient, username: str, refids: list[str]) -> None:
    api.write_checked("PATCH", ONE, MANY, {"name": username}, body={"cert": refids})


def remove_user(api: pfrest.PfrestClient, username: str) -> None:
    api.write_checked("DELETE", ONE, MANY, {"name": username})


def add_group(api: pfrest.PfrestClient, groupname: str) -> dict[str, Any]:
    group = {"name": groupname, "scope": "local", "description": ""}
    api.write_checked("POST", GROUP, GROUPS, {"name": groupname}, body={"scope": "local", "description": ""})
    return group


def manage_group(
    api: pfrest.PfrestClient, groupname: str, attributes: dict[str, Any], uid_to_name: dict[str, str]
) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for name, value in attributes.items():
        if name == "member":
            # config.xml stores uids, pfrest takes user names
            body[name] = [uid_to_name[str(uid)] for uid in value]
        elif name in ("description", "priv"):
            body[name] = value
        else:
            raise CommandExecutionError("unsupported attribute type", name)
    api.write_checked("PATCH", GROUP, GROUPS, {"name": groupname}, body=body)
    return dict(attributes, name=groupname)


def remove_group(api: pfrest.PfrestClient, groupname: str) -> None:
    api.write_checked("DELETE", GROUP, GROUPS, {"name": groupname})
