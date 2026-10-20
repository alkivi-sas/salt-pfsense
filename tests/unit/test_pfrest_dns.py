from typing import Any, Callable

import pytest

from conftest import ConfigPath, Loader, PfrestEnv
from fake_pfrest import Collection


def _setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch) -> Any:
    env = pfrest_env([Collection("system/dns", singleton=True)], data={"system/dns": {"dnsserver": ["9.9.9.9"]}})
    helper = ConfigPath({"system": {}})
    salt = dict(env.salt, **{"pfsense_gateway.has_gateway": bool, "cmd.run_all": helper.run_all})
    module = load_module("_modules/pfsense_dns.py", __salt__=salt)

    def config() -> dict[str, Any]:
        return {"system": dict(env.server.data["system/dns"], **helper.config["system"])}

    monkeypatch.setattr(module.pfsense_local, "read_config", config)
    return env, module, helper


def test_add_and_delete_dns(
    load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    env, module, _ = _setup(load_module, pfrest_env, monkeypatch)
    assert module.add_dns("1.1.1.1") == {"changes": {"dns": "1.1.1.1"}}
    assert env.server.data["system/dns"]["dnsserver"] == ["9.9.9.9", "1.1.1.1"]
    assert module.add_dns("1.1.1.1") == {"changes": None}
    assert module.del_dns("9.9.9.9") == {"changes": {"dns": "9.9.9.9"}}
    assert env.server.data["system/dns"]["dnsserver"] == ["1.1.1.1"]


def test_gateway_through_config_path(
    load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    env, module, helper = _setup(load_module, pfrest_env, monkeypatch)
    assert module.add_dns("1.1.1.1", gateway="WAN_DHCP") == {"changes": {"dns": "1.1.1.1", "gateway": "WAN_DHCP"}}
    assert helper.config["system"]["dns2gw"] == "WAN_DHCP" and helper.config["system"]["dns1gw"] == ""
    assert helper.applied == ["system_resolvconf_generate"]
    assert module.get_dns_gateway("1.1.1.1") == "WAN_DHCP"
