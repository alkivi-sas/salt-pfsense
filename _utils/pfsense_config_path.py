"""
Python side of helpers/config_path.php: read or write the config.xml paths pfrest does not model.

Call it inside a pfrest_module.session so the minion lock also covers these writes (V2, V4).
"""

import json
from typing import Any

from salt.exceptions import CommandExecutionError

HELPER = "/opt/helpers/config_path.php"


def _run(salt: Any, request: dict[str, Any]) -> dict[str, Any]:
    result = salt["cmd.run_all"](
        ["php", HELPER], stdin=json.dumps(request), python_shell=False, output_loglevel="quiet", ignore_retcode=True
    )
    if result["retcode"] != 0:
        raise CommandExecutionError(
            "config_path {0} {1} failed: {2}".format(request["op"], request["path"], result["stderr"])
        )
    response: dict[str, Any] = json.loads(result["stdout"])
    return response


def get_path(salt: Any, path: str) -> Any:
    return _run(salt, {"op": "get", "path": path})["value"]


def set_path(salt: Any, path: str, value: Any, apply: list[str] | None = None, test: bool = False) -> bool:
    if test:
        return get_path(salt, path) != value
    return bool(_run(salt, {"op": "set", "path": path, "value": value, "apply": apply or [], "desc": path})["changed"])


def delete_path(salt: Any, path: str, apply: list[str] | None = None, test: bool = False) -> bool:
    if test:
        return get_path(salt, path) is not None
    return bool(_run(salt, {"op": "delete", "path": path, "apply": apply or [], "desc": path})["changed"])
