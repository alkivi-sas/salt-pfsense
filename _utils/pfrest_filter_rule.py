"""
pfrest implementation of pfsense_filter_rule (firewall/rule).

The module keeps its FilterRule objects built from config.xml dicts: this file converts between the
config.xml representation and the pfrest one, so get_rule / list_rules / the state are unchanged.
Natural key: descr + interface (or floating), like the FauxAPI backend; ids are positions.
"""

import re
from typing import Any

from salt.exceptions import CommandExecutionError

import pfrest

ONE = "firewall/rule"
MANY = "firewall/rules"

# config.xml keys without pfrest field: refused when set, ignored when empty
UNSUPPORTED = ("max-src-states", "tagged", "statetimeout", "max", "max-src-nodes", "max-src-conn", "os")
PASSTHROUGH = ("descr", "type", "ipprotocol", "statetype", "direction", "tag", "gateway", "sched")
_INTERFACE = re.compile(r"^(wan|lan|opt\d+)$")
_SPECIAL = ("(self)", "pppoe", "l2tp")


def _endpoint_to_api(data: Any) -> tuple[str, str | None]:
    """config.xml source/destination dict -> (pfrest address string, port)."""
    data = data or {"any": ""}
    if "any" in data:
        address = "any"
    elif "address" in data:
        address = str(data["address"])
    elif "network" in data:
        network = str(data["network"])
        if network.endswith("ip") and _INTERFACE.match(network[:-2]):
            address = network[:-2] + ":ip"
        else:
            address = network
    else:
        raise CommandExecutionError("unexpected source/destination {0}".format(data))
    if "not" in data and address != "any":
        address = "!" + address
    port = data.get("port")
    return address, (str(port).replace("-", ":") if port not in (None, "") else None)


def _endpoint_from_api(address: str, port: Any) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if address.startswith("!"):
        data["not"] = ""
        address = address[1:]
    if address == "any":
        data["any"] = ""
    elif address.endswith(":ip") and _INTERFACE.match(address[:-3]):
        data["network"] = address[:-3] + "ip"
    elif _INTERFACE.match(address) or address in _SPECIAL:
        data["network"] = address
    else:
        data["address"] = address
    if port not in (None, ""):
        data["port"] = str(port).replace(":", "-")
    return data


def to_api(rule: dict[str, Any]) -> dict[str, Any]:
    """config.xml rule dict (FilterRule.to_dict) -> pfrest body. tracker is read-only on pfrest."""
    for key in UNSUPPORTED:
        if rule.get(key):
            raise CommandExecutionError("filter rule field {0} is not covered by pfrest".format(key))
    if rule.get("type") == "match":
        raise CommandExecutionError("match rules are not covered by pfrest")
    body: dict[str, Any] = {key: rule[key] for key in PASSTHROUGH if rule.get(key) not in (None, "")}
    body["interface"] = [i for i in str(rule.get("interface") or "").split(",") if i]
    protocol = rule.get("protocol")
    if protocol not in (None, "", "any"):
        body["protocol"] = protocol
    for side in ("source", "destination"):
        address, port = _endpoint_to_api(rule.get(side))
        body[side] = address
        if port is not None:
            body[side + "_port"] = port
    body["disabled"] = "disabled" in rule
    body["log"] = "log" in rule
    body["floating"] = rule.get("floating") in ("yes", True)
    if body["floating"]:
        body["quick"] = rule.get("quick") in ("yes", True)
    return body


def from_api(obj: dict[str, Any]) -> dict[str, Any]:
    """pfrest rule -> config.xml rule dict, as FauxAPI config_get returned it."""
    rule: dict[str, Any] = {key: obj[key] for key in PASSTHROUGH if obj.get(key) not in (None, "")}
    rule["interface"] = ",".join(obj.get("interface") or [])
    if obj.get("protocol"):
        rule["protocol"] = obj["protocol"]
    for side in ("source", "destination"):
        rule[side] = _endpoint_from_api(obj.get(side) or "any", obj.get(side + "_port"))
    for flag in ("disabled", "log"):
        if obj.get(flag):
            rule[flag] = ""
    if obj.get("floating"):
        rule["floating"] = "yes"
        if obj.get("quick"):
            rule["quick"] = "yes"
    if obj.get("tracker") is not None:
        rule["tracker"] = str(obj["tracker"])
    return rule


def config_rules(api: pfrest.PfrestClient) -> list[dict[str, Any]]:
    """All rules in config order, as config.xml dicts with their current pfrest id under '_id'."""
    return [dict(from_api(obj), _id=obj["id"]) for obj in api.get(MANY) or []]


def add_rule(api: pfrest.PfrestClient, rule: dict[str, Any], placement: int) -> None:
    api.post(ONE, dict(to_api(rule), placement=placement))


def rm_rules(api: pfrest.PfrestClient, matches: Any) -> int:
    """Delete every rule for which matches(config_dict) is true, re-resolving ids after each delete."""
    removed = 0
    while True:
        targets = [rule for rule in config_rules(api) if matches(rule)]
        if not targets:
            return removed
        api.delete(ONE, targets[0]["_id"])
        removed += 1
        if api.dry_run:
            return removed


def patch_rule(api: pfrest.PfrestClient, rule_id: int, changes: dict[str, Any]) -> None:
    """Patch the given config.xml keys (source, descr, log) of the rule at rule_id."""
    body: dict[str, Any] = {"id": rule_id}
    for key, value in changes.items():
        if key in ("source", "destination"):
            address, port = _endpoint_to_api(value)
            body[key] = address
            body[key + "_port"] = port
        elif key == "log":
            body["log"] = bool(value)
        else:
            body[key] = value
    api.patch(ONE, body)
