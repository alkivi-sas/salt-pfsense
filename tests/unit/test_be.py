import json
from typing import Any

from conftest import Loader

HELPER = "/opt/helpers/manage_bootenv.php"


def _run_all(calls: list[list[str]], stdout: str) -> Any:
    def run_all(cmd: list[str], python_shell: bool = False) -> dict[str, Any]:
        calls.append(cmd)
        return {"retcode": 0, "stdout": stdout}

    return run_all


def test_list_be_uses_deployed_helper(load_module: Loader) -> None:
    calls: list[list[str]] = []
    module = load_module("_modules/pfsense_be.py", __salt__={"cmd.run_all": _run_all(calls, "[]")})
    assert module.list_be() == []
    assert calls == [["php", HELPER, "--list"]]


def test_delete_be_uses_deployed_helper(load_module: Loader) -> None:
    calls: list[list[str]] = []
    stdout = json.dumps([{"name": "old", "status": "Inactive", "version": "26.03"}])
    module = load_module("_modules/pfsense_be.py", __salt__={"cmd.run_all": _run_all(calls, stdout)})
    module.delete_be("old")
    module.delete_be_for_version("26.03")
    assert [cmd[1] for cmd in calls] == [HELPER] * 4
