from typing import Any, Callable

import pytest
from salt.exceptions import CommandExecutionError

from conftest import Loader, PfrestEnv, bind
from fake_pfrest import Collection

ALIASES = [Collection("firewall/alias", "firewall/aliases")]


def _setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], test: bool = False, **kw: Any) -> Any:
    env = pfrest_env(ALIASES, **kw)
    module = load_module("_modules/pfsense_alias.py", __salt__=env.salt, __opts__={"test": test})
    state = load_module(
        "_states/pfsense_alias.py", __salt__=dict(env.salt, **bind(module, "pfsense_alias")), __opts__={"test": test}
    )
    return env, module, state


def test_present_create_idempotent_update_absent(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    env, module, state = _setup(load_module, pfrest_env)
    ret = state.present("ADMIN", ["192.0.2.1"], "host", descr="admins")
    assert ret["result"] is True
    assert env.server.objects("firewall/alias") == [
        {"name": "ADMIN", "type": "host", "address": ["192.0.2.1"], "descr": "admins"}
    ]
    assert env.server.applied == ["firewall/apply"]
    assert env.commands == [["/etc/rc.filter_synchronize"]]

    state.present("ADMIN", ["192.0.2.1"], "host", descr="admins")
    assert env.server.applied == ["firewall/apply"]

    state.present("ADMIN", ["192.0.2.1", "192.0.2.2"], "host", descr="admins")
    assert env.server.objects("firewall/alias")[0]["address"] == ["192.0.2.1", "192.0.2.2"]
    assert module.get_target("ADMIN") == ["192.0.2.1", "192.0.2.2"]

    state.absent("ADMIN")
    assert env.server.objects("firewall/alias") == []


def test_deferred_apply(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    env, module, _ = _setup(load_module, pfrest_env, apply_mode="deferred")
    module.set_target("ADMIN", ["192.0.2.1"], type="host")
    assert env.server.applied == []
    assert env.commands == [["/etc/rc.filter_synchronize"]]


def test_test_mode_writes_nothing(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    env, module, _ = _setup(load_module, pfrest_env, test=True)
    module.set_target("ADMIN", ["192.0.2.1"], type="host")
    assert env.server.objects("firewall/alias") == []
    assert env.server.applied == []


def test_type_change_refused(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    _, module, _ = _setup(load_module, pfrest_env)
    module.set_target("ADMIN", ["192.0.2.1"], type="host")
    with pytest.raises(CommandExecutionError, match="already present as host"):
        module.set_target("ADMIN", ["192.0.2.0/24"], type="network")


def test_urltable_not_covered(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    _, module, _ = _setup(load_module, pfrest_env)
    with pytest.raises(CommandExecutionError, match="URL table"):
        module.set_target("BLOCK", ["x"], type="urltable", url="https://example.org/list.txt")
