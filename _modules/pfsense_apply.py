"""
Apply pending pfrest changes of a domain (firewall, interface, routing, dhcp, wireguard).
Used with the deferred apply mode (pillar pfsense:pfrest:apply: deferred), see _utils/pfrest_module.py.
"""

import os
from typing import Any

import pfrest
import pfrest_module

__virtualname__ = "pfsense_apply"


def __virtual__() -> Any:
    if os.path.isfile("/etc/pf.os"):
        return __virtualname__
    return (False, "pfsense_apply: not a pfSense system")


def domains() -> list[str]:
    return sorted(pfrest.APPLY_ENDPOINTS)


def pending(domain: str) -> bool:
    return pfrest_module.client().pending(domain)


def apply(domain: str) -> bool:
    """Apply the domain synchronously, then sync HA. Return True."""
    pfrest_module.client().apply(domain)
    __salt__["cmd.run_all"](pfrest_module.HA_SYNC, python_shell=False)
    return True
