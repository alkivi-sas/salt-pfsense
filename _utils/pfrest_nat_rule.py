"""
pfrest implementation of pfsense_nat_rule (firewall/nat/port_forward).

Like pfrest_filter_rule, it converts between config.xml rules and pfrest objects so the NatRule
objects, their equality (the natural key) and the state are unchanged. No associated filter rule
is created, as with the FauxAPI backend.
"""

from typing import Any, Callable

import pfrest
from pfrest_filter_rule import endpoint_from_api, endpoint_to_api

ONE = "firewall/nat/port_forward"
MANY = "firewall/nat/port_forwards"


def to_api(rule: dict[str, Any]) -> dict[str, Any]:
    """NatRule.to_dict() -> PortForward body."""
    body: dict[str, Any] = {
        "interface": rule["interface"],
        "protocol": rule["protocol"],
        "target": rule["target"],
        "local_port": str(rule["local-port"]),
        "disabled": bool(rule.get("disabled")),
    }
    if rule.get("descr"):
        body["descr"] = rule["descr"]
    for side in ("source", "destination"):
        address, port = endpoint_to_api(rule.get(side))
        body[side] = address
        if port is not None:
            body[side + "_port"] = port
    return body


def from_api(obj: dict[str, Any]) -> dict[str, Any]:
    """PortForward -> config.xml rule dict, any written as NatRule's default ({'any': {}})."""
    rule: dict[str, Any] = {
        "descr": obj.get("descr") or None,
        "protocol": obj.get("protocol"),
        "target": obj.get("target"),
        "interface": obj.get("interface"),
        "local-port": obj.get("local_port"),
    }
    if obj.get("disabled"):
        rule["disabled"] = ""
    for side in ("source", "destination"):
        endpoint = endpoint_from_api(obj.get(side) or "any", obj.get(side + "_port"))
        if "any" in endpoint:
            endpoint["any"] = {}
        rule[side] = endpoint
    return rule


def config_rules(api: pfrest.PfrestClient) -> list[dict[str, Any]]:
    return [dict(from_api(obj), _id=obj["id"]) for obj in api.get(MANY) or []]


def add_rule(api: pfrest.PfrestClient, rule: dict[str, Any], index: int) -> None:
    api.post(ONE, dict(to_api(rule), placement=index))


def rm_rules(api: pfrest.PfrestClient, matches: Callable[[dict[str, Any]], bool]) -> int:
    removed = 0
    while True:
        targets = [rule for rule in config_rules(api) if matches(rule)]
        if not targets:
            return removed
        api.delete(ONE, targets[0]["_id"])
        removed += 1
        if api.dry_run:
            return removed
