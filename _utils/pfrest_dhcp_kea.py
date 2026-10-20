"""
pfrest implementation of the pfsense_dhcp_kea commit.

The translation (numberoptions -> Kea custom JSON) is unchanged; only the commit differs. The custom
JSON is not modelled by pfrest and goes through config_path, the backend through
services/dhcp_server/backend, last, so Kea never starts without its options. One DHCP apply follows.
"""

import copy
from typing import Any

from salt.exceptions import CommandExecutionError

import pfrest
import pfsense_config_path

BACKEND = "services/dhcp_server/backend"


def _dhcpd(config: dict[str, Any]) -> dict[str, Any]:
    dhcpd = config.get("dhcpd")
    return dhcpd if isinstance(dhcpd, dict) else {}


def _strip(config: dict[str, Any]) -> dict[str, Any]:
    """Config without the keys commit() handles, to detect any other pending change."""
    stripped = copy.deepcopy(config)
    stripped.pop("dhcpbackend", None)
    if isinstance(stripped.get("kea"), dict):
        stripped["kea"].pop("custom_kea_config", None)
        if not stripped["kea"]:
            # created by the migration to hold the global JSON
            stripped.pop("kea")
    for data in _dhcpd(stripped).values():
        if isinstance(data, dict):
            data.pop("custom_kea_config", None)
            data.pop("numberoptions", None)
    return stripped


def commit(api: pfrest.PfrestClient, salt: Any, original: dict[str, Any], pending: dict[str, Any]) -> bool:
    if _strip(original) != _strip(pending):
        raise CommandExecutionError("pending DHCP changes outside the Kea migration keys")
    test = api.dry_run
    changed = False

    def kea_json(config: dict[str, Any]) -> Any:
        kea = config.get("kea")
        return kea.get("custom_kea_config") if isinstance(kea, dict) else None

    if kea_json(pending) != kea_json(original):
        changed |= pfsense_config_path.set_path(salt, "kea/custom_kea_config", kea_json(pending), test=test)
    for interface, data in _dhcpd(pending).items():
        before = _dhcpd(original).get(interface) or {}
        for key in ("custom_kea_config", "numberoptions"):
            if data.get(key) != before.get(key):
                path = "dhcpd/{0}/{1}".format(interface, key)
                changed |= pfsense_config_path.set_path(salt, path, data.get(key), test=test)
    if (pending.get("dhcpbackend") or "isc") != (original.get("dhcpbackend") or "isc"):
        api.patch(BACKEND, {"dhcpbackend": pending["dhcpbackend"]})
        changed = True
    if changed and not test:
        # config_path writes do not mark the DHCP subsystem dirty: count them as writes for the apply
        api.writes += 1
    return changed
