from typing import Any, Callable

import pytest

from conftest import Loader, PfrestEnv, bind
from fake_pfrest import Collection

MAC_A = "02:00:5e:00:53:01"
MAC_B = "02:00:5e:00:53:02"


class Setup:
    def __init__(self, load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch):
        self.env = pfrest_env(
            [Collection("services/dhcp_server/static_mapping", "services/dhcp_server/static_mappings", parented=True)],
            data={"services/dhcp_server/static_mapping": {"lan": [], "opt1": []}},
        )
        self.module = load_module("_modules/pfsense_dhcp_static_map.py", __salt__=self.env.salt, __context__={})
        monkeypatch.setattr(self.module.pfsense_local, "read_config", self.config)
        salt = dict(self.env.salt, **bind(self.module, "pfsense_dhcp_static_map"))
        self.state = load_module("_states/pfsense_dhcp_static_map.py", __salt__=salt)

    def config(self) -> dict[str, Any]:
        store = self.env.server.data["services/dhcp_server/static_mapping"]
        return {"dhcpd": {iface: {"enable": "", "staticmap": [dict(m) for m in maps]} for iface, maps in store.items()}}

    def maps(self, interface: str = "lan") -> list[dict[str, Any]]:
        return self.env.server.objects("services/dhcp_server/static_mapping", interface)


@pytest.fixture
def setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch) -> Setup:
    return Setup(load_module, pfrest_env, monkeypatch)


def test_pending_then_apply(setup: Setup) -> None:
    setup.state.present("printer", "lan", MAC_A, "192.168.1.50", "printer", descr="Printer")
    assert setup.maps() == []
    assert setup.state.apply("apply")["changes"] == {"config": "applied"}
    assert setup.maps() == [{"mac": MAC_A, "ipaddr": "192.168.1.50", "hostname": "printer", "descr": "Printer"}]
    assert setup.env.server.applied == ["services/dhcp_server/apply"]

    setup.state.present("printer", "lan", MAC_A, "192.168.1.50", "printer", descr="Printer")
    assert setup.state.apply("apply")["changes"] == {}


def test_reassigned_ip_deletes_before_creating(setup: Setup) -> None:
    setup.module.set_static_map("lan", MAC_A, "192.168.1.50", "old")
    setup.module.apply()
    setup.module.rm_static_map("lan", MAC_A)
    setup.module.set_static_map("lan", MAC_B, "192.168.1.50", "new")
    assert setup.module.apply() is True
    writes = [(m, p) for m, p, _ in setup.env.server.requests if m != "GET" and "static_mapping" in p]
    assert writes[-2:] == [
        ("DELETE", "services/dhcp_server/static_mapping"),
        ("POST", "services/dhcp_server/static_mapping"),
    ]
    assert [m["mac"] for m in setup.maps()] == [MAC_B]


def test_update_ip(setup: Setup) -> None:
    setup.module.set_static_map("opt1", MAC_A, "10.0.1.20", "cam")
    setup.module.apply()
    setup.module.set_static_map("opt1", MAC_A, "10.0.1.21", "cam")
    setup.module.apply()
    assert setup.maps("opt1")[0]["ipaddr"] == "10.0.1.21"
