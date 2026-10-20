"""Reference scenarios run against the pfSense lab (see docs/migration/lab.md).

Each directory under scenarios/ holds create.sls, an optional modify.sls and absent.sls.
They must be reachable on the master as lab.<scenario>.<step> (copy or symlink scenarios/ to
<file_roots>/lab/). Environment:
- LAB_MINION: minion id of the lab firewall (required)
- LAB_SALT: command used to reach the master, default "salt" (e.g. "ssh master sudo salt")
"""

import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest

SCENARIOS = sorted(p.name for p in (Path(__file__).parent / "scenarios").iterdir() if p.is_dir())

# Known failures of the FauxAPI backend, fixed by the pfrest migration (lot 4)
KNOWN_ISSUES = {
    ("alias", "test_mode_result"): "test mode returns result True instead of None",
}

pytestmark = pytest.mark.lab


def _apply(scenario: str, step: str, test: bool = False) -> dict[str, Any]:
    minion = os.environ.get("LAB_MINION")
    if not minion:
        pytest.skip("LAB_MINION is not set")
    cmd = shlex.split(os.environ.get("LAB_SALT", "salt")) + [
        minion,
        "state.apply",
        "lab.{0}.{1}".format(scenario, step),
        "test={0}".format(test),
        "--out=json",
        "--static",
    ]
    output = subprocess.run(cmd, capture_output=True, text=True, timeout=600).stdout
    states = json.loads(output)[minion]
    assert isinstance(states, dict), states
    return states


def _changed(states: dict[str, Any]) -> list[str]:
    return [key for key, state in states.items() if state["changes"]]


def _failed(states: dict[str, Any]) -> list[str]:
    return [key for key, state in states.items() if state["result"] is False]


def _check(scenario: str, check: str, condition: bool, detail: Any) -> None:
    reason = KNOWN_ISSUES.get((scenario, check))
    if reason and not condition:
        pytest.xfail(reason)
    assert condition, "{0}: {1}".format(check, detail)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_scenario(scenario: str) -> None:
    has_modify = (Path(__file__).parent / "scenarios" / scenario / "modify.sls").exists()

    created = _apply(scenario, "create")
    _check(scenario, "create", not _failed(created) and bool(_changed(created)), created)

    again = _apply(scenario, "create")
    _check(scenario, "idempotence", not _failed(again) and not _changed(again), again)

    if has_modify:
        modified = _apply(scenario, "modify")
        _check(scenario, "modify", not _failed(modified) and bool(_changed(modified)), modified)

    planned = _apply(scenario, "absent", test=True)
    _check(scenario, "test_mode", not _failed(planned), planned)
    _check(scenario, "test_mode_result", any(s["result"] is None for s in planned.values()), planned)

    removed = _apply(scenario, "absent")
    _check(scenario, "absent", not _failed(removed) and bool(_changed(removed)), removed)

    removed_again = _apply(scenario, "absent")
    _check(scenario, "absent_idempotence", not _failed(removed_again) and not _changed(removed_again), removed_again)
