"""
pfrest implementation of the pfsense_dhcp_static_map commit (services/dhcp_server/static_mapping).

The module keeps its pending config workflow (setters edit a copy, apply() commits once); on pfrest the
copy comes from the local config.xml and apply() turns the difference into API calls: deletions first
(an IP can only be mapped once), then updates, then creations, then one DHCP apply.
Natural key: parent_id (interface) + mac.
"""

from typing import Any

from salt.exceptions import CommandExecutionError

import pfrest

ONE = "services/dhcp_server/static_mapping"
MANY = "services/dhcp_server/static_mappings"

STRINGS = ("ipaddr", "hostname", "cid", "descr", "domain", "gateway")
INTEGERS = ("defaultleasetime", "maxleasetime")
UNSUPPORTED = (
    "filename",
    "rootpath",
    "ddnsdomain",
    "ddnsdomainprimary",
    "ddnsdomainkeyname",
    "ddnsdomainkey",
    "tftp",
    "ldap",
)


def _maps(config: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result = {}
    dhcpd = config.get("dhcpd")
    if not isinstance(dhcpd, dict):
        return {}
    for interface, data in dhcpd.items():
        if not isinstance(data, dict):
            continue
        maps = data.get("staticmap") or []
        for static_map in [maps] if isinstance(maps, dict) else maps:
            result[(interface, static_map["mac"])] = static_map
    return result


def to_api(static_map: dict[str, Any]) -> dict[str, Any]:
    for key in UNSUPPORTED:
        if static_map.get(key):
            raise CommandExecutionError("static map field {0} is not covered by pfrest".format(key))
    body: dict[str, Any] = {key: static_map[key] for key in STRINGS if static_map.get(key) not in (None, "")}
    for key in INTEGERS:
        if static_map.get(key) not in (None, ""):
            body[key] = int(static_map[key])
    if static_map.get("domainsearchlist"):
        body["domainsearchlist"] = [d for d in str(static_map["domainsearchlist"]).split(";") if d]
    return body


def commit(api: pfrest.PfrestClient, original: dict[str, Any], pending: dict[str, Any]) -> bool:
    before, after = _maps(original), _maps(pending)
    removed = [key for key in before if key not in after]
    changed = [key for key in after if key in before and after[key] != before[key]]
    added = [key for key in after if key not in before]
    for interface, mac in removed:
        api.write_checked("DELETE", ONE, MANY, {"mac": mac}, parent_id=interface)
    for interface, mac in changed:
        api.write_checked("PATCH", ONE, MANY, {"mac": mac}, body=to_api(after[(interface, mac)]), parent_id=interface)
    for interface, mac in added:
        api.write_checked("POST", ONE, MANY, {"mac": mac}, body=to_api(after[(interface, mac)]), parent_id=interface)
    return bool(removed or changed or added)
