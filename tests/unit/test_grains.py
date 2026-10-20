import io
import os
from typing import Any

import pytest
import salt.utils.files

from conftest import Loader


@pytest.mark.parametrize(
    "version, installed, expected",
    [
        (
            "26.07-RELEASE\n",
            "2.10_2\n",
            {"pfsense_base": "26.07", "pfsense_edition": "Plus", "pfrest_version": "2.10_2"},
        ),
        ("2.8.1-RELEASE\n", None, {"pfsense_base": "2.8.1", "pfsense_edition": "CE", "pfrest_version": ""}),
    ],
)
def test_pfsense_grains(
    load_module: Loader, monkeypatch: pytest.MonkeyPatch, version: str, installed: str | None, expected: dict[str, str]
) -> None:
    def run_all(cmd: list[str], python_shell: bool = False) -> dict[str, Any]:
        if installed is None:
            return {"retcode": 1, "stdout": ""}
        return {"retcode": 0, "stdout": installed}

    files = {"/etc/version": version}
    monkeypatch.setattr(os.path, "isfile", lambda path: path in files)
    monkeypatch.setattr(salt.utils.files, "fopen", lambda path, mode="r": io.StringIO(files[path]))
    module = load_module("_grains/pfsense.py")
    monkeypatch.setitem(module.__salt__, "cmd.run_all", run_all)
    monkeypatch.setitem(module.__salt__, "cmd.run", lambda cmd: "non netgate")
    grains = module.pfsense_grains()
    assert {k: grains[k] for k in expected} == expected
