from typing import Any, Callable

import pytest

from conftest import FakeFauxapi, Loader

VLAN = {"vlanif": "igb1.10", "if": "igb1", "tag": "10", "descr": "voip", "pcp": ""}


@pytest.mark.parametrize("vlans", ["", {}])
def test_set_vlan_without_existing_vlans(
    load_module: Loader, fake_fauxapi: Callable[..., FakeFauxapi], monkeypatch: pytest.MonkeyPatch, vlans: Any
) -> None:
    module = load_module("_modules/pfsense_vlan.py")
    client = fake_fauxapi({"vlans": vlans})
    monkeypatch.setattr(module, "_get_client", lambda: client)
    assert module.set_vlan("igb1", 10, descr="voip") is True
    assert client.config["vlans"]["vlan"] == [VLAN]


def test_present_test_mode_on_existing_vlan(load_module: Loader) -> None:
    salt = {
        "pfsense_vlan.get_vlan": lambda interface, tag: VLAN,
        "pfsense_vlan.has_vlan": lambda interface, tag: True,
    }
    state = load_module("_states/pfsense_vlan.py", __salt__=salt, __opts__={"test": True})
    ret = state.present("voip", "igb1", 10, descr="voip")
    assert ret["result"] is True
    assert ret["comment"] == "VLAN is already OK"
