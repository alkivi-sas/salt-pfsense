"""
Shared plumbing for the pfrest branch of the Salt execution modules.

Each module keeps its public functions and dispatches to a _utils/pfrest_<domain>.py implementation
when its backend is pfrest (pillar pfsense:api_backend, see pfsense.get_backend).

Apply mode (pillar pfsense:pfrest:apply):
- immediate (default): the domain is applied at the end of each write, like the FauxAPI backend did;
- deferred: writes stay pending until a pfsense_apply state applies the domain once (V3).
"""

import contextlib
import functools
from typing import Any, Iterator

import pfrest
import pfsense
import pfsense_local

PILLAR_APPLY = "pfsense:pfrest:apply"
HA_SYNC = ["/etc/rc.filter_synchronize"]


def enabled(salt: Any, module: str) -> bool:
    return pfsense.get_backend(salt["config.get"], module) == "pfrest"


@functools.lru_cache(maxsize=1)
def _base_url() -> str:
    return pfsense_local.webgui_base_url(pfsense_local.read_config())


def client(test: bool = False) -> pfrest.PfrestClient:
    return pfrest.PfrestClient(base_url=_base_url(), dry_run=test)


@contextlib.contextmanager
def session(salt: Any, opts: Any, domain: str | None = None, ha_sync: bool = True) -> Iterator[pfrest.PfrestClient]:
    """Locked client for a read -> write sequence; applies the domain and syncs HA when something was written."""
    api = client(bool(opts.get("test", False)))
    with pfrest.config_lock(api):
        yield api
    if not api.writes or api.dry_run:
        return
    if domain and salt["config.get"](PILLAR_APPLY, "immediate") != "deferred":
        api.apply(domain)
    if ha_sync:
        salt["cmd.run_all"](HA_SYNC, python_shell=False)
