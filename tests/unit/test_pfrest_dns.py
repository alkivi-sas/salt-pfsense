from typing import Any, Callable

import pytest
from salt.exceptions import CommandExecutionError

from conftest import Loader, PfrestEnv
from fake_pfrest import Collection


def _setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch) -> Any:
    env = pfrest_env([Collection("system/dns", singleton=True)], data={"system/dns": {"dnsserver": ["9.9.9.9"]}})
    module = load_module("_modules/pfsense_dns.py", __salt__=dict(env.salt, **{"pfsense_gateway.has_gateway": bool}))
    monkeypatch.setattr(module.pfsense_local, "read_config", lambda: {"system": dict(env.server.data["system/dns"])})
    return env, module


def test_add_and_delete_dns(
    load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    env, module = _setup(load_module, pfrest_env, monkeypatch)
    assert module.add_dns("1.1.1.1") == {"changes": {"dns": "1.1.1.1"}}
    assert env.server.data["system/dns"]["dnsserver"] == ["9.9.9.9", "1.1.1.1"]
    assert module.add_dns("1.1.1.1") == {"changes": None}
    assert module.del_dns("9.9.9.9") == {"changes": {"dns": "9.9.9.9"}}
    assert env.server.data["system/dns"]["dnsserver"] == ["1.1.1.1"]


def test_gateway_not_covered(
    load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, module = _setup(load_module, pfrest_env, monkeypatch)
    with pytest.raises(CommandExecutionError, match="gateways are not covered"):
        module.add_dns("1.1.1.1", gateway="WAN_DHCP")
