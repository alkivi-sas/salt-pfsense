from typing import Any, Callable

import pytest

from conftest import FakeFauxapi, Loader

PUBKEY = "A" * 43 + "="


def _config() -> dict[str, Any]:
    peer = {
        "descr": "laptop",
        "tun": "tun_wg0",
        "publickey": PUBKEY,
        "allowedips": {"row": [{"address": "10.6.0.2", "mask": "32", "descr": ""}]},
    }
    return {"installedpackages": {"wireguard": {"peers": {"item": [peer]}}}}


def test_add_peer_duplicate_publickey(
    load_module: Loader, fake_fauxapi: Callable[..., FakeFauxapi], monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module("_modules/pfsense_wireguard.py")
    client = fake_fauxapi(_config())
    monkeypatch.setattr(module, "_get_client", lambda: client)
    result = module.add_peer("phone", "tun_wg0", PUBKEY, "10.6.0.3")
    assert result == "Peer laptop have the same publickey {0}".format(PUBKEY)
