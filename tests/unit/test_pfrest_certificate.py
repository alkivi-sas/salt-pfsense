import base64
from typing import Any, Callable

import pytest

from conftest import Loader, PfrestEnv
from fake_pfrest import Collection, FakePfrest

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
B64 = base64.b64encode(PEM.encode()).decode()
CONFIG: dict[str, Any] = {
    "ca": [{"refid": "ca1", "descr": "VPN CA", "serial": "4"}],
    "crl": [
        {"refid": "crl1", "descr": "VPN CRL", "caref": "ca1", "lifetime": "730", "serial": "1", "method": "internal"}
    ],
    "cert": [{"refid": "c1", "descr": "alice", "caref": "ca1", "type": "user", "crt": B64, "prv": "UFJW"}],
    "system": {"user": [{"name": "alice", "uid": "2000", "descr": "Alice", "cert": ["c1"]}]},
}


def _generate(server: FakePfrest, body: dict[str, Any]) -> dict[str, Any]:
    cert = {"refid": "new1", "descr": body["descr"], "type": "user", "crt": PEM, "prv": "PRIVATE"}
    server.data["system/certificate"].append(cert)
    return cert


@pytest.fixture
def setup(load_module: Loader, pfrest_env: Callable[..., PfrestEnv], monkeypatch: pytest.MonkeyPatch) -> Any:
    env = pfrest_env(
        [
            Collection("system/certificate", "system/certificates"),
            Collection("system/certificate/generate"),
            Collection("system/crl/revoked_certificate", parented=True),
        ],
        data={"system/certificate": [], "system/crl/revoked_certificate": {}},
        pfsense__pki__dn={"country": "FR", "organization": "Example"},
    )
    env.server.hooks["system/certificate/generate"] = _generate
    added: list[tuple[str, str]] = []
    salt = dict(
        env.salt,
        **{
            "pfsense_user.get_user": lambda name: (0, CONFIG["system"]["user"][0]) if name == "alice" else (None, None),
            "pfsense_user.add_cert": lambda username, refid: added.append((username, refid)),
        }
    )
    module = load_module("_modules/pfsense_certificate.py", __salt__=salt)
    monkeypatch.setattr(module.pfsense_local, "read_config", lambda: CONFIG)
    return env, module, added


def test_add_user_certificate_generates_through_api(setup: Any) -> None:
    env, module, added = setup
    CONFIG["system"]["user"][0]["cert"] = []
    try:
        cert, error = module.add_user_certificate("alice")
    finally:
        CONFIG["system"]["user"][0]["cert"] = ["c1"]
    assert error is None
    assert cert == {"refid": "new1", "descr": "alice", "caref": "ca1", "type": "user"}
    assert added == [("alice", "new1")]
    body = [b for m, p, b in env.server.requests if p == "system/certificate/generate"][0]
    assert body["dn_commonname"] == "alice" and body["dn_country"] == "FR" and body["dn_organization"] == "Example"
    assert body["keylen"] == 2048 and body["digest_alg"] == "sha256"


def test_revoke_user_certificate(setup: Any) -> None:
    env, module, _ = setup
    assert module.revoke_user_certificate("alice") == "Revocation OK"
    assert env.server.objects("system/crl/revoked_certificate", 0) == [{"certref": "c1", "reason": 5}]


def test_import_cert_sends_pem(setup: Any) -> None:
    env, module, _ = setup
    module.add_cert("ignored", "server", B64, base64.b64encode(b"KEY").decode(), cert_type="server")
    assert env.server.objects("system/certificate")[0] == {
        "descr": "server",
        "crt": PEM,
        "prv": "KEY",
        "type": "server",
    }
