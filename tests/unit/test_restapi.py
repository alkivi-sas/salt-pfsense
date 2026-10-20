import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from salt.exceptions import CommandExecutionError

import pfrest
from conftest import Loader
from fake_pfrest import Collection, FakePfrest

KEY = "ab" * 32


class Cmd:
    def __init__(self, installed: str = "", stdout: str = '{"changed": true}') -> None:
        self.installed = installed
        self.stdout = stdout
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, cmd: list[str], **kwargs: Any) -> dict[str, Any]:
        self.calls.append((cmd, kwargs))
        if cmd[:2] == ["pkg", "query"]:
            return {"retcode": 0 if self.installed else 1, "stdout": self.installed, "stderr": ""}
        return {"retcode": 0, "stdout": self.stdout, "stderr": ""}


@pytest.fixture
def setup(load_module: Loader, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    def make(installed: str = "", version: str = "26.07-RELEASE", pillar: dict[str, Any] | None = None) -> Any:
        cmd = Cmd(installed)
        values = {"pfsense:restapi:api_key": KEY}
        values.update(pillar or {})
        salt = {"cmd.run_all": cmd, "pillar.get": lambda key, default=None: values.get(key, default)}
        module = load_module("_modules/pfsense_restapi.py", __salt__=salt)
        monkeypatch.setattr(module, "_base_edition", lambda: module.lifecycle.parse_version(version))
        monkeypatch.setattr(pfrest, "API_KEY_FILE", str(tmp_path / "etc" / "api.key"))
        return module, cmd

    return make


def test_install_when_missing(setup: Any) -> None:
    module, cmd = setup()
    assert module.install() == {"old": "", "new": "2.10_2"}
    assert cmd.calls[-1][0][:4] == ["pkg-static", "-C", "/dev/null", "add"]


def test_install_already_pinned(setup: Any) -> None:
    module, cmd = setup(installed="2.10_2")
    assert module.install() == {}
    assert len(cmd.calls) == 1


def test_install_other_version_reverts(setup: Any) -> None:
    module, cmd = setup(installed="2.7_7")
    assert module.install(test=True) == {"old": "2.7_7", "new": "2.10_2"}
    assert len(cmd.calls) == 1
    module.install()
    assert cmd.calls[-1][0] == ["pfsense-restapi", "revert", "v2.10.2"]


def test_install_unsupported_base(setup: Any) -> None:
    module, _ = setup(version="2.7.2-RELEASE")
    with pytest.raises(CommandExecutionError, match="no package"):
        module.install()


def test_bootstrap_never_exposes_the_key(setup: Any) -> None:
    module, cmd = setup()
    changes = module.bootstrap()
    assert changes == {"key_file": "updated", "config": "user, group, key and auth methods updated"}
    helper, kwargs = cmd.calls[-1]
    assert helper == ["php", "/opt/helpers/restapi_bootstrap.php"]
    assert kwargs["output_loglevel"] == "quiet"
    request = json.loads(kwargs["stdin"])
    assert KEY not in kwargs["stdin"] and KEY not in json.dumps(changes)
    assert request["key_hash"] == module.lifecycle.key_hash(KEY)
    assert not any("command-prompt" in p for p in request["privileges"])
    path = Path(pfrest.API_KEY_FILE)
    assert path.read_text() == KEY + "\n"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_bootstrap_rejects_bad_pillar_key(setup: Any) -> None:
    module, _ = setup(pillar={"pfsense:restapi:api_key": "short"})
    with pytest.raises(CommandExecutionError, match="hexadecimal"):
        module.bootstrap()


def test_bootstrap_test_mode_up_to_date(setup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    module, cmd = setup()
    module.bootstrap()
    monkeypatch.setattr(module, "status", lambda: {"version": "26.07"})
    assert module.bootstrap(test=True) == {}


def test_configure_settings_and_access_list(setup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    module, _ = setup()
    server = FakePfrest(
        [
            Collection("system/restapi/settings", singleton=True),
            Collection("system/restapi/access_list/entry", "system/restapi/access_list"),
        ],
        data={"system/restapi/settings": {"enabled": True, "auth_methods": ["BasicAuth", "KeyAuth"]}},
    )
    monkeypatch.setattr(module, "client", lambda test=False: pfrest.PfrestClient(api_key=KEY, session=server))
    changes = module.configure()
    assert changes["settings"]["auth_methods"] == {"old": ["BasicAuth", "KeyAuth"], "new": ["KeyAuth"]}
    assert server.data["system/restapi/settings"]["represent_interfaces_as"] == "id"
    assert server.objects("system/restapi/access_list/entry")[0]["network"] == "127.0.0.1/32"
    assert module.configure() == {}


def test_state_test_mode(load_module: Loader) -> None:
    salt = {"pfsense_restapi.install": lambda test=False, version=None: {"old": "", "new": "2.10_2"}}
    state = load_module("_states/pfsense_restapi.py", __salt__=salt, __opts__={"test": True})
    ret = state.installed("pfrest")
    assert ret["result"] is None and ret["changes"] == {"old": "", "new": "2.10_2"}
