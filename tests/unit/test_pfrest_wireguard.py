from typing import Any, Callable

import pytest

from conftest import Loader, PfrestEnv
from fake_pfrest import Collection

PUBKEY = "B" * 43 + "="
PSK = "C" * 43 + "="


def test_add_peer(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch) -> None:
    env = pfrest_env([Collection("vpn/wireguard/peer", "vpn/wireguard/peers")], data={"vpn/wireguard/peer": []})
    module = load_module("_modules/pfsense_wireguard.py", __salt__=env.salt)
    config: dict[str, Any] = {
        "installedpackages": {
            "wireguard": {"tunnels": {"item": [{"name": "tun_wg0", "addresses": ""}]}, "peers": {"item": []}}
        }
    }
    monkeypatch.setattr(module.pfsense_local, "read_config", lambda: config)

    peer = module.add_peer("laptop", "tun_wg0", PUBKEY, "10.6.0.2", presharedkey=PSK)
    created = env.server.objects("vpn/wireguard/peer")[0]
    assert created["enabled"] is True and created["presharedkey"] == PSK
    assert created["allowedips"] == [{"address": "10.6.0.2", "mask": 32, "descr": ""}]
    assert PSK not in str(peer)
    assert env.server.applied == ["vpn/wireguard/apply"]
    assert not [c for c in env.commands if "regenerate_wireguard" in " ".join(c)]
