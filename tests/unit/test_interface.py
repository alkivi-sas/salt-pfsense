from typing import Any, Callable

import pytest

from conftest import FakeFauxapi, Loader

CONFIG = {
    "interfaces": {
        "opt1": {
            "if": "igb2",
            "ipaddr": "192.0.2.1",
            "subnet": "24",
            "descr": "VOIP",
            "enable": "",
            "spoofmac": "",
            "blockbogons": "",
        }
    }
}

WANTED = {"if": "igb2", "ipaddr": "192.0.2.1", "subnet": "24", "descr": "VOIP", "enable": "", "spoofmac": ""}


@pytest.fixture
def module(load_module: Loader, fake_fauxapi: Callable[..., FakeFauxapi], monkeypatch: pytest.MonkeyPatch) -> Any:
    module = load_module("_modules/pfsense_interface.py")
    client = fake_fauxapi(CONFIG)
    monkeypatch.setattr(module, "_get_client", lambda: client)
    return module


def test_need_changes_none(module: Any) -> None:
    assert module.need_changes("opt1", dict(WANTED, blockbogons="")) == []


def test_need_changes_value_and_booleans(module: Any) -> None:
    wanted = dict(WANTED, descr="PHONES", blockpriv="")
    assert sorted(module.need_changes("opt1", wanted)) == ["blockbogons", "blockpriv", "descr"]


def test_present_test_mode_on_existing_interface(load_module: Loader, module: Any) -> None:
    salt = {"pfsense_interface.has_interface": lambda name: True, "pfsense_interface.need_changes": module.need_changes}
    state = load_module("_states/pfsense_interface.py", __salt__=salt, __opts__={"test": True})
    ret = state.present("opt1", "igb2", "192.0.2.1", 24, "VOIP")
    assert ret["comment"] == "Interface is already OK"
