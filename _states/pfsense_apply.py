"""
Apply a pfrest domain once per run, after the states that changed it::

    firewall-applied:
      pfsense_apply.applied:
        - name: firewall
        - onchanges:
          - pfsense_alias: admin-alias
          - pfsense_filter_rule: admin-rule

Only needed with pillar pfsense:pfrest:apply: deferred; in immediate mode each write applies itself.
"""

from typing import Any


def applied(name: str, domain: str | None = None) -> dict[str, Any]:
    domain = domain or name
    ret: dict[str, Any] = {"name": name, "changes": {}, "result": True, "comment": ""}
    if domain not in __salt__["pfsense_apply.domains"]():
        ret["result"] = False
        ret["comment"] = "Unknown domain {0}".format(domain)
        return ret
    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "Domain {0} would be applied".format(domain)
        return ret
    __salt__["pfsense_apply.apply"](domain)
    ret["changes"] = {domain: "applied"}
    ret["comment"] = "Domain {0} applied".format(domain)
    return ret


def mod_watch(name: str, **kwargs: Any) -> dict[str, Any]:
    return applied(name, kwargs.get("domain"))
