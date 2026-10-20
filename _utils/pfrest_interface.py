"""
pfrest implementation of the pfsense_interface writes (interface, ids are wan/lan/optN).

Reads stay on the local config.xml: list_wan_interfaces / list_lan_interfaces run at Jinja render
time and rely on the config.xml ipaddr values (dhcp, pppoe). Writes are applied with interface/apply.
"""

from typing import Any

from salt.exceptions import CommandExecutionError

import pfrest

ONE = "interface"
MANY = "interfaces"
BOOLEANS = ("enable", "blockbogons", "blockpriv")
TYPEV6 = ("dhcp6", "slaac", "track6", "6to4", "6rd")


def to_api(wanted: dict[str, Any]) -> dict[str, Any]:
    """set_interface wanted data (booleans present as '') -> NetworkInterface body."""
    body: dict[str, Any] = {"if": wanted["if"], "descr": wanted["descr"]}
    for flag in BOOLEANS:
        body[flag] = flag in wanted
    for key in ("spoofmac", "gateway"):
        if wanted.get(key) not in (None, ""):
            body[key] = wanted[key]

    ipaddr = str(wanted.get("ipaddr") or "")
    if ipaddr == "dhcp":
        body["typev4"] = "dhcp"
    elif ipaddr == "pppoe":
        raise CommandExecutionError("PPPoE interfaces are not covered by pfrest")
    elif ipaddr in ("", "none"):
        body["typev4"] = "none"
    else:
        body.update(typev4="static", ipaddr=ipaddr, subnet=int(wanted["subnet"]))

    ipaddrv6 = str(wanted.get("ipaddrv6") or "")
    if ipaddrv6 in TYPEV6:
        body["typev6"] = ipaddrv6
    elif ipaddrv6:
        body.update(typev6="staticv6", ipaddrv6=ipaddrv6, subnetv6=int(wanted["subnetv6"]))
    else:
        body["typev6"] = "none"
    return body


def set_interface(api: pfrest.PfrestClient, interface: str, wanted: dict[str, Any], exists: bool) -> None:
    body = to_api(wanted)
    if exists:
        api.patch(ONE, dict(body, id=interface))
        return
    created = api.post(ONE, body)
    # pfrest assigns the next optN itself: refuse a silent mismatch with the asked name
    if not api.dry_run and created and created.get("id") != interface:
        raise CommandExecutionError("pfrest assigned {0} instead of {1}".format(created.get("id"), interface))


def rm_interface(api: pfrest.PfrestClient, interface: str) -> None:
    api.delete(ONE, interface)
