import base64
import json
from typing import Any, Callable

import pytest
from salt.exceptions import CommandExecutionError

from conftest import ConfigPath, Loader, PfrestEnv
from fake_pfrest import Collection

OPTIONS = {
    "43": {"name": "unificontroller", "type": "binary", "format": "hex"},
    "132": {"name": "yealink-vlan", "type": "string", "always-send": True},
}


def _item(number: str, value: str) -> dict[str, str]:
    return {"number": number, "type": "text", "value": base64.b64encode(value.encode()).decode()}


def _setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch) -> Any:
    env = pfrest_env(
        [Collection("services/dhcp_server/backend", singleton=True)],
        data={"services/dhcp_server/backend": {"dhcpbackend": "isc"}},
    )
    helper = ConfigPath(
        {
            "dhcpd": {
                "lan": {
                    "enable": "",
                    "numberoptions": {"item": [_item("43", "01:04:C0:00:02:0A"), _item("132", "200")]},
                }
            }
        }
    )
    events: list[str] = []

    def run_all(cmd: list[str], stdin: str = "", **kwargs: Any) -> dict[str, Any]:
        if stdin and json.loads(stdin)["op"] != "get":
            events.append("config_path " + json.loads(stdin)["path"])
        return helper.run_all(cmd, stdin=stdin, **kwargs)

    server_request = env.server.request

    def request(method: str, url: str, **kwargs: Any) -> Any:
        if method != "GET" and "config_history" not in url:
            events.append("{0} {1}".format(method, url.split("/api/v2/")[1]))
        return server_request(method, url, **kwargs)

    env.server.request = request  # type: ignore[method-assign]
    salt = dict(
        env.salt,
        **{
            "config.get": lambda key, default=None: (
                OPTIONS if key == "pfsense:dhcp_kea:options" else env.pillar.get(key, default)
            ),
            "cmd.run_all": run_all,
        }
    )

    def config() -> dict[str, Any]:
        return dict(helper.config, dhcpbackend=env.server.data["services/dhcp_server/backend"]["dhcpbackend"])

    module = load_module("_modules/pfsense_dhcp_kea.py", __salt__=salt, __context__={})
    monkeypatch.setattr(module.pfsense_local, "read_config", config)
    return env, module, helper, events


def test_migrate_on_pfrest(
    load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    env, module, helper, events = _setup(load_module, pfrest_env, monkeypatch)
    assert set(module.migrate()) == {"lan", "global", "dhcpbackend"}
    assert module.apply() is True
    assert events == [
        "config_path kea/custom_kea_config",
        "config_path dhcpd/lan/custom_kea_config",
        "config_path dhcpd/lan/numberoptions",
        "PATCH services/dhcp_server/backend",
        "POST services/dhcp_server/apply",
    ]
    assert env.server.data["services/dhcp_server/backend"]["dhcpbackend"] == "kea"
    assert helper.config["dhcpd"]["lan"]["numberoptions"] == ""
    assert module.migration_changes() == {}


def test_other_pending_change_refused(
    load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, module, _, _ = _setup(load_module, pfrest_env, monkeypatch)
    module.migrate()
    module._get_pending_config()["dhcpd"]["lan"]["range"] = {"from": "192.168.1.10"}
    with pytest.raises(CommandExecutionError, match="outside the Kea migration keys"):
        module.apply()
