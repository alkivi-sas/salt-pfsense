"""Modules whose data pfrest does not model: they go through helpers/config_path.php."""

import copy
from typing import Any, Callable

import pytest

from conftest import ConfigPath, Loader, PfrestEnv
from fake_pfrest import Collection


@pytest.fixture
def gap(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch) -> Any:
    def make(
        module_name: str,
        config: dict[str, Any],
        collections: list[Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> Any:
        env = pfrest_env(collections or [], data=data or {})
        helper = ConfigPath(copy.deepcopy(config))
        env.salt["cmd.run_all"] = helper.run_all
        env.salt["cmd.run"] = lambda cmd, **kw: helper.commands.append([cmd])
        module = load_module("_modules/{0}.py".format(module_name), __salt__=env.salt)
        monkeypatch.setattr(module.pfsense_local, "read_config", lambda: helper.config)
        return module, helper, env

    return make


def test_althostname(gap: Any) -> None:
    module, helper, _ = gap("pfsense_althostname", {"system": {"webgui": {"althostnames": "fw.example.org"}}})
    module.add_hostname("vpn.example.org")
    assert helper.config["system"]["webgui"]["althostnames"] == "fw.example.org vpn.example.org"
    module.rm_hostname("fw.example.org")
    assert module.list_hostnames() == ["vpn.example.org"]
    assert ["/etc/rc.filter_synchronize"] in helper.commands


def test_sshguard_whitelist(gap: Any) -> None:
    module, helper, _ = gap("pfsense_sshguard_whitelist", {"system": {"sshguard_whitelist": "192.0.2.0/24"}})
    module.add_ip("198.51.100.0/24")
    assert helper.config["system"]["sshguard_whitelist"] == "192.0.2.0/24 198.51.100.0/24"
    assert helper.applied == ["filter_configure", "system_syslogd_start"]
    assert not [c for c in helper.commands if "sshguard_whitelist.php" in " ".join(c)]
    module.rm_ip("192.0.2.0/24")
    assert module.list_ips() == ["198.51.100.0/24"]


def test_if_pppoe(gap: Any) -> None:
    module, helper, _ = gap("pfsense_if_pppoe", {"system": {}})
    module.enable(reboot=True)
    assert helper.config["system"]["use_if_pppoe"] == ""
    assert [["shutdown -r +1"]] == [c for c in helper.commands if c == ["shutdown -r +1"]]
    assert module.status() is True
    module.disable(reboot=False)
    assert module.status() is False


@pytest.mark.parametrize(
    "module_name, key", [("pfsense_sudo_configuration", "sudo"), ("pfsense_zabbix_configuration", "zabbixagentlts")]
)
def test_package_settings(gap: Any, module_name: str, key: str) -> None:
    config = {"installedpackages": {key: {"config": [{"enable": "on"}]}}}
    module, helper, _ = gap(module_name, config)
    module.set_value("enable", "off")
    assert helper.config["installedpackages"][key]["config"][0]["enable"] == "off"
    assert module.get_value("enable") == "off"


def test_zabbix_userparams_stay_base64(gap: Any) -> None:
    module, helper, _ = gap(
        "pfsense_zabbix_configuration", {"installedpackages": {"zabbixagentlts": {"config": [{"userparams": ""}]}}}
    )
    module.set_value("userparams", "UserParameter=users,who | wc -l")
    assert (
        helper.config["installedpackages"]["zabbixagentlts"]["config"][0]["userparams"]
        != "UserParameter=users,who | wc -l"
    )
    assert module.get_value("userparams") == "UserParameter=users,who | wc -l"


def test_webgui_settings(gap: Any) -> None:
    module, helper, env = gap(
        "pfsense_webgui_settings",
        {"system": {"webgui": {"protocol": "https", "port": "443"}}},
        collections=[Collection("system/webgui/settings", singleton=True)],
        data={"system/webgui/settings": {"protocol": "https", "port": 443, "sslcertref": "c1"}},
    )
    module.set_setting("nodnsrebindcheck", True)
    assert helper.config["system"]["webgui"]["nodnsrebindcheck"] == ""
    module.set_setting("nodnsrebindcheck", False)
    assert "nodnsrebindcheck" not in helper.config["system"]["webgui"]
    module.set_setting("port", "8443")
    assert env.server.data["system/webgui/settings"]["port"] == 8443
