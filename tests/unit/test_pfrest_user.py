import base64
from typing import Any, Callable

import pytest

from conftest import Loader, PfrestEnv, bind
from fake_pfrest import Collection

HASH = "$2y$10$" + "b" * 53
KEYS = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample admin@laptop"


class Setup:
    def __init__(self, load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch):
        self.env = pfrest_env(
            [Collection("user", "users"), Collection("user/group", "user/groups")],
            data={"user": [{"name": "admin", "uid": 0, "scope": "system"}], "user/group": []},
        )
        self.fields: dict[str, dict[str, Any]] = {}
        self.module = load_module("_modules/pfsense_user.py", __salt__=self.env.salt)
        monkeypatch.setattr(self.module.pfsense_local, "read_config", self.config)
        monkeypatch.setattr(self.module, "_set_fields", self.set_fields)
        salt = dict(self.env.salt, **bind(self.module, "pfsense_user"))
        self.state = load_module("_states/pfsense_user.py", __salt__=salt)

    def set_fields(self, username: str, fields: dict[str, Any]) -> bool:
        self.fields.setdefault(username, {}).update(fields)
        return True

    def config(self) -> dict[str, Any]:
        """config.xml as pfSense stores what pfrest and the helper wrote."""
        users = []
        for index, obj in enumerate(self.env.server.objects("user")):
            user = {k: v for k, v in obj.items() if k not in ("password", "disabled", "authorizedkeys")}
            user.setdefault("uid", 2000 + index)
            if obj.get("authorizedkeys"):
                user["authorizedkeys"] = base64.b64encode(obj["authorizedkeys"].encode()).decode()
            if obj.get("disabled"):
                user["disabled"] = ""
            user.update(self.fields.get(obj["name"], {}))
            users.append(user)
        return {"system": {"user": users, "group": list(self.env.server.objects("user/group"))}}


@pytest.fixture
def setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch) -> Setup:
    return Setup(load_module, pfrest_env, monkeypatch)


def test_present_creates_then_is_idempotent(setup: Setup) -> None:
    b64 = base64.b64encode(KEYS.encode()).decode()
    ret = setup.state.present(
        "ro.admin", password=HASH, descr="Read only", priv=["page-dashboard-all"], authorizedkeys=b64
    )
    assert ret["result"] is True and "password" not in ret["changes"]
    created = setup.env.server.objects("user")[1]
    assert created["authorizedkeys"] == KEYS and created["priv"] == ["page-dashboard-all"]
    assert created["password"] != HASH
    assert setup.fields == {"ro.admin": {"bcrypt-hash": HASH}}
    assert setup.env.commands == [["/etc/rc.filter_synchronize"]]

    again = setup.state.present(
        "ro.admin", password=HASH, descr="Read only", priv=["page-dashboard-all"], authorizedkeys=b64
    )
    assert again["changes"] == {}


def test_update_disable_and_remove(setup: Setup) -> None:
    setup.state.present("ro.admin", descr="Read only")
    setup.state.present("ro.admin", descr="Read only", disabled=True)
    assert setup.env.server.objects("user")[1]["disabled"] is True
    setup.state.absent("ro.admin")
    assert [u["name"] for u in setup.env.server.objects("user")] == ["admin"]
    assert not [c for c in setup.env.commands if c[0] != "/etc/rc.filter_synchronize"]


def test_add_cert_appends(setup: Setup) -> None:
    setup.module.add_user("vpn.user", {"descr": "VPN"})
    setup.module.add_cert("vpn.user", "65a1b2c3d4e5f")
    setup.module.add_cert("vpn.user", "75a1b2c3d4e5f")
    assert setup.env.server.objects("user")[1]["cert"] == ["65a1b2c3d4e5f", "75a1b2c3d4e5f"]


def test_group_members_are_names(setup: Setup) -> None:
    setup.module.add_user("vpn.user", {"descr": "VPN"})
    setup.module.add_group("vpn")
    uid = setup.config()["system"]["user"][1]["uid"]
    setup.module.manage_group("vpn", {"member": [str(uid)], "priv": ["user-services-captiveportal-login"]})
    assert setup.env.server.objects("user/group")[0]["member"] == ["vpn.user"]
    setup.module.remove_group("vpn")
    assert setup.env.server.objects("user/group") == []
