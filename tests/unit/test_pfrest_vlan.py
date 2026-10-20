from typing import Any, Callable

from conftest import Loader, PfrestEnv, bind
from fake_pfrest import Collection


def _setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> Any:
    env = pfrest_env([Collection("interface/vlan", "interface/vlans")], data={"interface/vlan": []})
    module = load_module("_modules/pfsense_vlan.py", __salt__=env.salt)
    state = load_module("_states/pfsense_vlan.py", __salt__=dict(env.salt, **bind(module, "pfsense_vlan")))
    return env, state


def test_vlan_lifecycle_is_idempotent(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    env, state = _setup(load_module, pfrest_env)
    assert state.present("voip", "igb1", 10, descr="VOIP")["changes"] == {"igb1.10": "New"}
    assert env.server.objects("interface/vlan") == [{"if": "igb1", "tag": 10, "descr": "VOIP"}]
    requests = len(env.server.requests)

    assert state.present("voip", "igb1", 10, descr="VOIP")["changes"] == {}
    assert not [r for r in env.server.requests[requests:] if r[0] != "GET"]

    state.present("voip", "igb1", 10, descr="Phones", pcp=5)
    assert env.server.objects("interface/vlan")[0] == {"if": "igb1", "tag": 10, "descr": "Phones", "pcp": 5}

    assert state.absent("voip", "igb1", 10)["changes"] == {"igb1.10": "Removed"}
    assert env.server.objects("interface/vlan") == []
