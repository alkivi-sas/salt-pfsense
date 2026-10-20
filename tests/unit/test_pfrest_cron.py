from typing import Any, Callable

import pytest

from conftest import Loader, PfrestEnv, bind
from fake_pfrest import Collection

COMMAND = "/usr/local/bin/backup.sh"


def test_cron_lifecycle(
    load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = pfrest_env([Collection("services/cron/job", "services/cron/jobs")], data={"services/cron/job": []})
    module = load_module("_modules/pfsense_cron.py", __salt__=env.salt)

    def config() -> dict[str, Any]:
        return {"cron": {"item": [dict(job) for job in env.server.objects("services/cron/job")]}}

    monkeypatch.setattr(module.pfsense_local, "read_config", config)
    state = load_module("_states/pfsense_cron.py", __salt__=dict(env.salt, **bind(module, "pfsense_cron")))

    created = state.present(COMMAND, "backup", minute=0, hour=3)
    assert created["changes"]
    job = env.server.objects("services/cron/job")[0]
    assert job == {
        "mday": "*",
        "hour": "3",
        "month": "*",
        "wday": "*",
        "minute": "0",
        "command": COMMAND,
        "who": "root",
    }

    assert state.present(COMMAND, "backup", minute=0, hour=3)["changes"] == {}

    state.present(COMMAND, "backup", minute=30, hour=3)
    assert env.server.objects("services/cron/job")[0]["minute"] == "30"

    state.absent(COMMAND, "backup")
    assert env.server.objects("services/cron/job") == []
    assert env.commands == []
