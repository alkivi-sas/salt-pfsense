from typing import Any, Callable

import pytest
from salt.exceptions import CommandExecutionError

import pfrest_interface as conv
from conftest import Loader, PfrestEnv
from fake_pfrest import Collection


def _config_from(env: PfrestEnv) -> Callable[[], dict[str, Any]]:
    def config() -> dict[str, Any]:
        interfaces = {}
        for key, obj in env.server.data["interface"].items():
            data = {"if": obj["if"], "descr": obj["descr"]}
            if obj.get("typev4") == "static":
                data.update(ipaddr=obj["ipaddr"], subnet=str(obj["subnet"]))
            elif obj.get("typev4") == "dhcp":
                data["ipaddr"] = "dhcp"
            for flag in ("enable", "blockbogons", "blockpriv"):
                if obj.get(flag):
                    data[flag] = ""
            interfaces[key] = data
        return {
            "interfaces": interfaces,
            "gateways": {
                "gateway_item": [{"name": "WAN_DHCP", "interface": "wan", "ipprotocol": "inet", "gateway": "dynamic"}]
            },
        }

    return config


@pytest.fixture
def setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch) -> Any:
    env = pfrest_env(
        [Collection("interface", "interfaces", keyed=True)],
        data={
            "interface": {
                "wan": {"if": "igb0", "descr": "WAN", "typev4": "dhcp", "enable": True},
                "lan": {
                    "if": "igb1",
                    "descr": "LAN",
                    "typev4": "static",
                    "ipaddr": "192.168.1.1",
                    "subnet": 24,
                    "enable": True,
                },
            }
        },
    )
    module = load_module("_modules/pfsense_interface.py", __salt__=env.salt)
    monkeypatch.setattr(module.pfsense_local, "read_config", _config_from(env))
    return env, module


def test_to_api() -> None:
    body = conv.to_api({"if": "igb2", "descr": "VOIP", "ipaddr": "10.0.20.1", "subnet": "24", "enable": ""})
    assert body == {
        "if": "igb2",
        "descr": "VOIP",
        "enable": True,
        "blockbogons": False,
        "blockpriv": False,
        "typev4": "static",
        "ipaddr": "10.0.20.1",
        "subnet": 24,
        "typev6": "none",
    }
    assert conv.to_api({"if": "igb0", "descr": "WAN", "ipaddr": "dhcp"})["typev4"] == "dhcp"
    with pytest.raises(CommandExecutionError, match="PPPoE"):
        conv.to_api({"if": "igb0", "descr": "WAN", "ipaddr": "pppoe"})


def test_lists_and_set_interface(setup: Any) -> None:
    env, module = setup
    assert list(module.list_wan_interfaces()) == ["wan"]
    module.set_interface("opt1", "igb2", "10.0.20.1", 24, "VOIP", blockbogons=True)
    assert env.server.data["interface"]["opt1"]["typev4"] == "static"
    assert env.server.applied == ["interface/apply"]
    module.set_interface("opt1", "igb2", "10.0.20.1", 24, "PHONES")
    assert env.server.data["interface"]["opt1"]["descr"] == "PHONES"
    module.rm_interface("opt1")
    assert "opt1" not in env.server.data["interface"]


def test_created_id_must_match(setup: Any) -> None:
    _, module = setup
    with pytest.raises(CommandExecutionError, match="assigned opt1 instead of opt5"):
        module.set_interface("opt5", "igb5", "10.0.50.1", 24, "LAB")


def test_gateway_reads_local_config(load_module: Loader, setup: Any) -> None:
    env, interface = setup
    salt = dict(env.salt, **{"pfsense_interface.list_interfaces": interface.list_interfaces})
    gateway = load_module("_modules/pfsense_gateway.py", __salt__=salt)
    assert gateway.has_gateway("WAN_DHCP") is True
