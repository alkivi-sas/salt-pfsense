from typing import Any

from conftest import Loader

CRON = {
    "minute": "0",
    "hour": "3",
    "mday": "*",
    "month": "*",
    "wday": "*",
    "who": "root",
    "command": "/usr/local/bin/backup.sh",
    "identifier": "backup",
}


def _state(load_module: Loader, test: bool, calls: list[str]) -> Any:
    def manage_cron(*args: Any) -> dict[str, str]:
        calls.append("manage_cron")
        return CRON

    salt = {"pfsense_cron.get_cron": lambda identifier, name: dict(CRON), "pfsense_cron.manage_cron": manage_cron}
    return load_module("_states/pfsense_cron.py", __salt__=salt, __opts__={"test": test})


def test_present_is_idempotent_with_integer_schedule(load_module: Loader) -> None:
    calls: list[str] = []
    state = _state(load_module, False, calls)
    ret = state.present(CRON["command"], "backup", minute=0, hour=3)
    assert ret["changes"] == {}
    assert calls == []


def test_present_test_mode_reports_update(load_module: Loader) -> None:
    calls: list[str] = []
    state = _state(load_module, True, calls)
    ret = state.present(CRON["command"], "backup", minute=30, hour=3)
    assert ret["changes"]["minute"] == "30"
    assert calls == []
