from typing import Any, Callable

import pytest
from salt.exceptions import CommandExecutionError

import pfrest_filter_rule as conv
from conftest import Loader, PfrestEnv, bind
from fake_pfrest import Collection

RULES = [Collection("firewall/rule", "firewall/rules")]


def _api_rule(descr: str, interface: str, **extra: Any) -> dict[str, Any]:
    rule = {
        "descr": descr,
        "type": "pass",
        "interface": [interface],
        "ipprotocol": "inet",
        "source": "any",
        "destination": "any",
        "tracker": 100,
    }
    rule.update(extra)
    return rule


def _setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], rules: list[dict[str, Any]]) -> Any:
    env = pfrest_env(RULES, data={"firewall/rule": rules})
    module = load_module("_modules/pfsense_filter_rule.py", __salt__=env.salt)
    state = load_module(
        "_states/pfsense_filter_rule.py", __salt__=dict(env.salt, **bind(module, "pfsense_filter_rule"))
    )
    return env, module, state


@pytest.mark.parametrize(
    "config, api",
    [
        ({"any": ""}, ("any", None)),
        ({"address": "ADMIN_ALIAS"}, ("ADMIN_ALIAS", None)),
        ({"address": "198.51.100.0/24", "port": "8000-8100"}, ("198.51.100.0/24", "8000:8100")),
        ({"network": "wanip", "port": "443"}, ("wan:ip", "443")),
        ({"network": "opt2"}, ("opt2", None)),
        ({"network": "(self)", "not": ""}, ("!(self)", None)),
    ],
)
def test_endpoint_round_trip(config: dict[str, Any], api: tuple[str, str | None]) -> None:
    assert conv._endpoint_to_api(config) == api
    assert conv._endpoint_from_api(*api) == config


def test_unsupported_field_refused() -> None:
    with pytest.raises(CommandExecutionError, match="max-src-conn"):
        conv.to_api({"descr": "x", "interface": "lan", "max-src-conn": "10"})


def test_present_places_rule_in_interface_group(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    env, _, state = _setup(load_module, pfrest_env, [_api_rule("lan any", "lan"), _api_rule("wan old", "wan")])
    ret = state.present(
        "wan https",
        interface="wan",
        type="pass",
        protocol="tcp",
        source={"address": "ADMIN_ALIAS"},
        destination={"network": "wanip", "port": 443},
    )
    assert ret["result"] is True
    rules = env.server.objects("firewall/rule")
    assert [r["descr"] for r in rules] == ["lan any", "wan https", "wan old"]
    created = rules[1]
    assert created["interface"] == ["wan"] and created["source"] == "ADMIN_ALIAS"
    assert created["destination"] == "wan:ip" and created["destination_port"] == "443"
    assert "tracker" not in created
    assert env.server.applied == ["firewall/apply"]

    again = state.present("wan https", interface="wan", type="pass", protocol="tcp")
    assert again["comment"] == "Rule is already present"
    assert len(env.server.objects("firewall/rule")) == 3


def test_absent_removes_all_duplicates(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    rules = [_api_rule("dup", "lan"), _api_rule("keep", "lan"), _api_rule("dup", "lan"), _api_rule("dup", "wan")]
    env, _, state = _setup(load_module, pfrest_env, rules)
    assert state.absent("dup", interface="lan")["result"] is True
    assert [(r["descr"], r["interface"]) for r in env.server.objects("firewall/rule")] == [
        ("keep", ["lan"]),
        ("dup", ["wan"]),
    ]


def test_enable_logging_for_all_rules(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    env, module, _ = _setup(load_module, pfrest_env, [_api_rule("a", "lan", log=True), _api_rule("b", "wan")])
    assert len(module.enable_logging_for_all_rules()) == 1
    assert all(r["log"] for r in env.server.objects("firewall/rule"))


def test_get_rule_by_tracker(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    _, module, _ = _setup(load_module, pfrest_env, [_api_rule("a", "lan", tracker=1700000000)])
    rule = module.get_rule(tracker=1700000000, interface="lan")
    assert rule is not None and rule.descr == "a"
