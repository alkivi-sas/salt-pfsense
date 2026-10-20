from typing import Any

import pytest

from conftest import Loader


def test_export_openvpn_config_first_certificate(load_module: Loader, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def run_all(cmd: list[str], python_shell: bool = False) -> dict[str, Any]:
        calls.append(cmd)
        return {"retcode": 0, "stdout": "/tmp/alice.zip"}

    salt = {
        "pfsense_openvpn.list_servers": lambda: {"1": {"caref": "ca1"}},
        "pfsense_certificate.list_ca": lambda: {"ca1": {}},
        "pfsense_certificate.get_cert": lambda refid: {"refid": refid, "caref": "ca1"},
        "pfsense_certificate.get_cert_index": lambda refid: 0,
        "cmd.run_all": run_all,
    }
    module = load_module("_modules/pfsense_user.py", __salt__=salt)
    monkeypatch.setattr(module, "get_user", lambda username: (3, {"name": username, "cert": ["c1"]}))
    assert module.export_openvpn_config("alice", "vpn.example.org") == "/tmp/alice.zip"
    assert calls == [["php", "/opt/helpers/export_openvpn_config.php", "1", "0", "ca1", "vpn.example.org", "confzip"]]
