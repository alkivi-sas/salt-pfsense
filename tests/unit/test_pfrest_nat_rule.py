from typing import Callable

from conftest import Loader, PfrestEnv, bind
from fake_pfrest import Collection

RULE = {
    "protocol": "tcp",
    "target": "192.0.2.20",
    "interface": "wan",
    "local_port": "8443",
    "destination": {"network": "wanip", "port": "18443"},
}


def test_port_forward_lifecycle(load_module: Loader, pfrest_env: Callable[..., PfrestEnv]) -> None:
    existing = {
        "interface": "wan",
        "protocol": "udp",
        "target": "192.0.2.5",
        "local_port": "1194",
        "source": "any",
        "destination": "wan:ip",
        "destination_port": "1194",
        "descr": "vpn",
    }
    env = pfrest_env(
        [Collection("firewall/nat/port_forward", "firewall/nat/port_forwards")],
        data={"firewall/nat/port_forward": [existing]},
    )
    module = load_module("_modules/pfsense_nat_rule.py", __salt__=env.salt)
    state = load_module("_states/pfsense_nat_rule.py", __salt__=dict(env.salt, **bind(module, "pfsense_nat_rule")))

    assert state.present("https", **RULE)["result"] is True
    rules = env.server.objects("firewall/nat/port_forward")
    assert rules[0]["descr"] == "https" and rules[1]["descr"] == "vpn"
    assert rules[0]["destination"] == "wan:ip" and rules[0]["destination_port"] == "18443"
    assert rules[0]["source"] == "any"
    assert env.server.applied == ["firewall/apply"]

    state.present("https", **RULE)
    assert len(env.server.objects("firewall/nat/port_forward")) == 2

    state.absent("https", **RULE)
    assert [r["descr"] for r in env.server.objects("firewall/nat/port_forward")] == ["vpn"]
