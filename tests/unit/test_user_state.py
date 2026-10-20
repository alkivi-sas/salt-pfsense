from typing import Any

from conftest import Loader

HASH = "$2y$10$" + "a" * 53


def _state(load_module: Loader, user: dict[str, Any], calls: list[Any]) -> Any:
    salt = {
        "pfsense_user.get_user": lambda name: (0, dict(user)),
        "pfsense_user.manage_user": lambda name, attributes: calls.append(attributes) or {"name": name},
    }
    return load_module("_states/pfsense_user.py", __salt__=salt)


def test_present_same_password_hash_is_idempotent(load_module: Loader) -> None:
    calls: list[Any] = []
    state = _state(load_module, {"descr": "Admin", "bcrypt-hash": HASH}, calls)
    ret = state.present("admin2", password=HASH, descr="Admin")
    assert ret["changes"] == {}
    assert calls == []


def test_present_new_password_hash_updates(load_module: Loader) -> None:
    calls: list[Any] = []
    state = _state(load_module, {"descr": "Admin", "bcrypt-hash": "$2y$10$old"}, calls)
    state.present("admin2", password=HASH, descr="Admin")
    assert calls == [{"password": HASH, "descr": "Admin"}]
