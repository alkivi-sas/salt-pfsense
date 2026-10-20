import base64
from typing import Any, Callable

import pytest

from conftest import Loader, PfrestEnv
from fake_pfrest import Collection

KEY = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + bytes(range(32))).decode()


def _config_from(env: PfrestEnv) -> Callable[[], dict[str, Any]]:
    def config() -> dict[str, Any]:
        users = []
        for obj in env.server.objects("user"):
            keys = obj.get("authorizedkeys") or ""
            users.append({"name": obj["name"], "authorizedkeys": base64.b64encode(keys.encode()).decode()})
        return {"system": {"user": users}}

    return config


def test_set_check_and_remove_key(
    load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = pfrest_env([Collection("user", "users")], data={"user": [{"name": "admin", "authorizedkeys": ""}]})
    module = load_module("_modules/pfsense_ssh.py", __salt__=env.salt)
    monkeypatch.setattr(module.pfsense_local, "read_config", _config_from(env))

    assert module.set_auth_key("admin", KEY, enc="ssh-ed25519", comment="admin@laptop") == "new"
    assert env.server.objects("user")[0]["authorizedkeys"].strip() == "ssh-ed25519 {0} admin@laptop".format(KEY)
    assert module.check_key("admin", KEY, enc="ssh-ed25519", comment="admin@laptop") == "exists"
    assert module.set_auth_key("admin", KEY, enc="ssh-ed25519", comment="admin@laptop") == "no change"

    assert module.rm_auth_key("admin", KEY) == "Key removed"
    assert env.server.objects("user")[0]["authorizedkeys"] == ""
