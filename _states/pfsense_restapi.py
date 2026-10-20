"""
States for the pfSense-pkg-RESTAPI lifecycle. Order them first in the firewall highstate::

    pfrest-installed:
      pfsense_restapi.installed: []
    pfrest-bootstrapped:
      pfsense_restapi.bootstrapped:
        - require:
          - pfsense_restapi: pfrest-installed
    pfrest-configured:
      pfsense_restapi.configured:
        - require:
          - pfsense_restapi: pfrest-bootstrapped
"""

from typing import Any, Callable


def _run(name: str, function: Callable[..., dict[str, Any]], comment: str, **kwargs: Any) -> dict[str, Any]:
    ret: dict[str, Any] = {"name": name, "changes": {}, "result": True, "comment": ""}
    test = __opts__["test"]
    changes = function(test=test, **kwargs)
    if not changes:
        ret["comment"] = "{0} already up to date".format(comment)
        return ret
    ret["changes"] = changes
    ret["result"] = None if test else True
    ret["comment"] = "{0} {1}".format(comment, "would be updated" if test else "updated")
    return ret


def installed(name: str, version: str | None = None) -> dict[str, Any]:
    """Pinned pfSense-pkg-RESTAPI is installed (reinstalled after a pfSense upgrade)."""
    return _run(name, __salt__["pfsense_restapi.install"], "pfSense-pkg-RESTAPI", version=version)


def bootstrapped(name: str) -> dict[str, Any]:
    """Dedicated API user, group and key exist, KeyAuth is enabled."""
    return _run(name, __salt__["pfsense_restapi.bootstrap"], "REST API bootstrap")


def configured(name: str, settings: dict[str, Any] | None = None) -> dict[str, Any]:
    """REST API settings and access list match the wanted values."""
    return _run(name, __salt__["pfsense_restapi.configure"], "REST API settings", settings=settings)
