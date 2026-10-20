import base64
import json
from typing import Any, Callable

import pytest
from salt.exceptions import CommandExecutionError

from conftest import FakeFauxapi, Loader

OPTIONS = {
    "43": {"name": "unificontroller", "type": "binary", "format": "hex"},
    "132": {"name": "yealink-vlan", "type": "string", "always-send": True},
}

OPTION_DEF = {
    "option-def": [
        {"code": 43, "name": "unificontroller", "space": "dhcp4", "type": "binary"},
        {"code": 132, "name": "yealink-vlan", "space": "dhcp4", "type": "string"},
    ]
}


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("utf-8")


def _json_b64(data: Any) -> str:
    return _b64(json.dumps(data))


def _item(number: str, value: str) -> dict[str, str]:
    return {"number": number, "type": "text", "value": _b64(value)}


def _config(**lan: Any) -> dict[str, Any]:
    interface = {"enable": "", "numberoptions": {"item": [_item("43", "01:04:C0:00:02:0A"), _item("132", "200")]}}
    interface.update(lan)
    return {"dhcpd": {"lan": interface, "opt1": {"range": {}}}}


class Kea:
    def __init__(self, load_module: Loader, client: FakeFauxapi, monkeypatch: pytest.MonkeyPatch) -> None:
        self.ha_sync: list[list[str]] = []
        salt = {
            "config.get": lambda key, default: OPTIONS,
            "cmd.run_all": lambda cmd, python_shell=False: self.ha_sync.append(cmd),
        }
        self.module = load_module("_modules/pfsense_dhcp_kea.py", __salt__=salt)
        self.client = client
        monkeypatch.setattr(self.module, "_get_client", lambda: client)


@pytest.fixture
def kea(
    load_module: Loader, fake_fauxapi: Callable[..., FakeFauxapi], monkeypatch: pytest.MonkeyPatch
) -> Callable[[dict[str, Any]], Kea]:
    return lambda config: Kea(load_module, fake_fauxapi(config), monkeypatch)


def test_migrate_converts_options_and_switches_backend(kea: Callable[[dict[str, Any]], Kea]) -> None:
    k = kea(_config())
    changes = k.module.migrate()
    assert set(changes) == {"lan", "global", "dhcpbackend"}
    assert k.module.apply() is True

    config = k.client.config
    assert config["dhcpbackend"] == "kea"
    assert config["dhcpd"]["lan"]["numberoptions"] == ""
    lan = json.loads(base64.b64decode(config["dhcpd"]["lan"]["custom_kea_config"]))
    assert lan == {
        "option-data": [
            {"name": "unificontroller", "data": "0104C000020A"},
            {"name": "yealink-vlan", "data": "200", "always-send": True},
        ]
    }
    assert json.loads(base64.b64decode(config["kea"]["custom_kea_config"])) == OPTION_DEF
    assert ("function_call", {"function": "services_dhcpd_configure", "includes": ["services.inc"]}) in k.client.calls
    assert k.ha_sync == [["/etc/rc.filter_synchronize"]]


def test_second_run_has_no_changes(kea: Callable[[dict[str, Any]], Kea]) -> None:
    k = kea(_config())
    k.module.migrate()
    k.module.apply()
    assert k.module.migration_changes() == {}
    assert k.module.apply() is False


def test_single_option_item_as_dict(kea: Callable[[dict[str, Any]], Kea]) -> None:
    k = kea(_config(numberoptions={"item": _item("132", "200")}))
    wanted = k.module.numberoptions_to_kea("lan")
    assert wanted == {"option-data": [{"name": "yealink-vlan", "data": "200", "always-send": True}]}


def test_firewall_without_dhcp_only_switches_backend(kea: Callable[[dict[str, Any]], Kea]) -> None:
    k = kea({"dhcpd": ""})
    assert k.module.migration_changes() == {"dhcpbackend": {"old": "isc", "new": "kea"}}


@pytest.mark.parametrize(
    "lan, message",
    [
        ({"failover_peerip": "192.0.2.2"}, "failover"),
        ({"numberoptions": {"item": [_item("66", "tftp.example.org")]}}, "Option 66"),
        ({"numberoptions": {"item": [_item("43", "not-hex")]}}, "not hex"),
        ({"custom_kea_config": _json_b64({"option-data": []})}, "different Kea custom config"),
    ],
)
def test_refuses_unsafe_migration(kea: Callable[[dict[str, Any]], Kea], lan: dict[str, Any], message: str) -> None:
    k = kea(_config(**lan))
    with pytest.raises(CommandExecutionError, match=message):
        k.module.migration_changes()


def test_refuses_divergent_global_config(kea: Callable[[dict[str, Any]], Kea]) -> None:
    config = _config()
    config["kea"] = {"custom_kea_config": _json_b64({"option-def": []})}
    k = kea(config)
    with pytest.raises(CommandExecutionError, match="different global custom config"):
        k.module.migration_changes()
