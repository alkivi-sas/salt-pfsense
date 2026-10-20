from typing import Callable

from conftest import Loader, PfrestEnv, bind


def test_applied_state(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    env = pfrest_env([])
    module = load_module("_modules/pfsense_apply.py", __salt__=env.salt)
    state = load_module("_states/pfsense_apply.py", __salt__=bind(module, "pfsense_apply"))
    assert state.applied("firewall")["changes"] == {"firewall": "applied"}
    assert env.server.applied == ["firewall/apply"]
    assert env.commands == [["/etc/rc.filter_synchronize"]]
    assert state.applied("nope")["result"] is False


def test_applied_test_mode(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    env = pfrest_env([])
    module = load_module("_modules/pfsense_apply.py", __salt__=env.salt)
    state = load_module("_states/pfsense_apply.py", __salt__=bind(module, "pfsense_apply"), __opts__={"test": True})
    assert state.mod_watch("dhcp")["result"] is None
    assert env.server.applied == []
