from pathlib import Path
from typing import Any, Callable

import pytest

from conftest import Loader, PfrestEnv
from fake_pfrest import Collection, FakePfrest

CONFIG = {
    "openvpn": {"openvpn-server": [{"vpnid": "3", "caref": "ca0"}, {"vpnid": "1", "caref": "ca1"}]},
    "installedpackages": {"vpn_openvpn_export": {"serverconfig": {"item": [{"server": "1", "useaddr": "other"}]}}},
    "system": {"user": [{"name": "alice", "cert": ["c1"]}]},
}


def test_export_openvpn_config(
    load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env = pfrest_env([Collection("vpn/openvpn/client_export")])
    exports: list[dict[str, Any]] = []

    def export(server: FakePfrest, body: dict[str, Any]) -> tuple[str, bytes]:
        exports.append(body)
        return "pfSense-UDP4-1194-alice.zip", b"PK\x03\x04"

    env.server.hooks["vpn/openvpn/client_export"] = export
    salt = dict(
        env.salt,
        **{
            "pfsense_openvpn.list_servers": lambda: {"1": {"caref": "ca1"}, "3": {"caref": "ca0"}},
            "pfsense_certificate.list_ca": lambda: {"ca1": {}},
            "pfsense_certificate.get_cert": lambda refid: {"refid": refid, "caref": "ca1"},
            "pfsense_certificate.get_cert_index": lambda refid: 0,
        }
    )
    module = load_module("_modules/pfsense_user.py", __salt__=salt)
    monkeypatch.setattr(module.pfsense_local, "read_config", lambda: CONFIG)
    monkeypatch.setattr(module.pfrest_openvpn, "EXPORT_DIR", str(tmp_path))

    path = module.export_openvpn_config("alice", "vpn.example.org", vpnid=1)
    assert path == str(tmp_path / "pfSense-UDP4-1194-alice.zip")
    assert Path(path).read_bytes() == b"PK\x03\x04"
    assert exports == [
        {
            "verifyservercn": "auto",
            "legacy": False,
            "silent": True,
            "bindmode": "nobind",
            "p12encryption": "high",
            "id": 0,
            "server": 1,
            "type": "confzip",
            "username": "alice",
            "certref": "c1",
            "useaddr": "other",
            "useaddr_hostname": "vpn.example.org",
        }
    ]
