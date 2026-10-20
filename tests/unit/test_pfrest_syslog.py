from typing import Any, Callable

import pytest
from salt.exceptions import CommandExecutionError

from conftest import Loader, PfrestEnv, bind
from fake_pfrest import Collection

# Key/value pairs used by the syslog SLS of the states repository
SLS = [
    ("remoteserver", "198.51.100.5:5140"),
    ("enable", True),
    ("ipproto", "ipv4"),
    ("sourceip", ""),
    ("nentries", "500"),
    ("logfilesize", "1024000"),
    ("rotatecount", "99"),
    ("format", "rfc5424"),
    ("reverse", True),
    ("logconfigchanges", "enabled"),
    ("disablelocallogging", True),
    ("nologprivatenets", False),
    ("nologbogons", False),
    ("nologdefaultblock", False),
    ("nologdefaultpass", True),
    ("nolognginx", False),
    ("logall", True),
]


def _setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> Any:
    env = pfrest_env(
        [Collection("status/logs/settings", singleton=True)],
        data={"status/logs/settings": {"format": "rfc3164", "nentries": 50, "logfilesize": 512000}},
    )
    module = load_module("_modules/pfsense_syslog_configuration.py", __salt__=env.salt)
    salt = dict(env.salt, **bind(module, "pfsense_syslog_configuration"))
    return env, module, load_module("_states/pfsense_syslog_configuration.py", __salt__=salt)


def test_sls_is_applied_then_idempotent(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    env, module, state = _setup(load_module, pfrest_env)
    first = [state.present(name, value) for name, value in SLS]
    assert sum(1 for ret in first if ret["changes"]) >= 10
    settings = env.server.data["status/logs/settings"]
    assert settings["enableremotelogging"] is True and settings["reverseorder"] is True
    assert settings["nentries"] == 500 and settings["logconfigchanges"] is True
    second = [state.present(name, value) for name, value in SLS]
    assert [ret["name"] for ret in second if ret["changes"]] == []
    assert env.commands == []
    assert module.force_reload() is True


def test_unmodelled_setting_refused(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    _, module, _ = _setup(load_module, pfrest_env)
    with pytest.raises(CommandExecutionError, match="numberofitems"):
        module.get_setting("numberofitems")
