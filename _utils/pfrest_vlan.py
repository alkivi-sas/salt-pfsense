"""pfrest implementation of pfsense_vlan (interface/vlan, always applied, natural key: if + tag)."""

from typing import Any

import pfrest

ONE = "interface/vlan"
MANY = "interface/vlans"


def _legacy(obj: dict[str, Any]) -> dict[str, Any]:
    pcp = obj.get("pcp")
    return {
        "vlanif": obj.get("vlanif") or "{0}.{1}".format(obj["if"], obj["tag"]),
        "if": obj["if"],
        "tag": str(obj["tag"]),
        "descr": obj.get("descr") or "",
        "pcp": "" if pcp is None else str(pcp),
    }


def list_vlans(api: pfrest.PfrestClient) -> dict[str, dict[str, Any]]:
    vlans = (_legacy(obj) for obj in api.get(MANY) or [])
    return {vlan["vlanif"]: vlan for vlan in vlans}


def set_vlan(api: pfrest.PfrestClient, interface: str, tag: int, descr: str, pcp: str) -> bool:
    key = {"if": interface, "tag": int(tag)}
    body: dict[str, Any] = {"descr": descr}
    if pcp != "":
        body["pcp"] = int(pcp)
    current = api.find_one(MANY, allow_missing=True, **key)
    if current is None:
        api.write_checked("POST", ONE, MANY, key, body=body)
    elif _legacy(current)["descr"] != descr or _legacy(current)["pcp"] != str(pcp):
        # if and tag are the identity: changing them would destroy the VLAN interface
        api.write_checked("PATCH", ONE, MANY, key, body=body)
    return True


def rm_vlan(api: pfrest.PfrestClient, interface: str, tag: int) -> bool:
    api.write_checked("DELETE", ONE, MANY, {"if": interface, "tag": int(tag)})
    return True
