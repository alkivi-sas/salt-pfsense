import json
from typing import Any, Callable

import pytest
from salt.exceptions import CommandExecutionError

from conftest import FakeFauxapi, Loader

NEW_CERT = {"refid": "c9", "descr": "alice", "crt": "CRT", "prv": "PRV", "caref": "ca1", "type": "user"}


def _config() -> dict[str, Any]:
    return {"ca": [{"refid": "ca1", "descr": "VPN CA", "serial": "4"}], "cert": []}


@pytest.fixture
def setup(
    load_module: Loader, fake_fauxapi: Callable[..., FakeFauxapi], monkeypatch: pytest.MonkeyPatch
) -> tuple[Any, FakeFauxapi, list[Any]]:
    added: list[Any] = []

    def run_all(cmd: list[str], python_shell: bool = False) -> dict[str, Any]:
        return {"retcode": 0, "stdout": json.dumps(NEW_CERT)}

    salt = {
        "cmd.run_all": run_all,
        "pfsense_user.get_user": lambda username: (0, {"name": username}),
        "pfsense_user.add_cert": lambda username, refid: added.append((username, refid)),
    }
    module = load_module("_modules/pfsense_certificate.py", __salt__=salt)
    client = fake_fauxapi(_config())
    monkeypatch.setattr(module, "_get_client", lambda: client)
    return module, client, added


def test_add_user_certificate_with_single_ca(setup: tuple[Any, FakeFauxapi, list[Any]]) -> None:
    module, client, added = setup
    cert, error = module.add_user_certificate("alice")
    assert error is None
    assert cert == NEW_CERT
    assert added == [("alice", "c9")]
    assert client.config["ca"][0]["serial"] == "5"


def test_get_ca_unknown_returns_none(setup: tuple[Any, FakeFauxapi, list[Any]]) -> None:
    module, _, _ = setup
    assert module.get_ca("missing") is None


def test_increase_ca_serial_failure(setup: tuple[Any, FakeFauxapi, list[Any]], monkeypatch: pytest.MonkeyPatch) -> None:
    module, client, _ = setup
    monkeypatch.setattr(client, "config_patch", lambda config: {"message": "error"})
    with pytest.raises(CommandExecutionError):
        module._increase_ca_serial("ca1")


def test_user_cert_state_reports_creation_error(load_module: Loader) -> None:
    salt = {
        "pfsense_user.get_user": lambda name: (0, {"name": name}),
        "pfsense_certificate.list_ca": lambda: {"ca1": {}},
        "pfsense_certificate.get_ca": lambda refid: {"descr": "VPN CA"},
        "pfsense_certificate.add_user_certificate": lambda name, caref: (None, "boom"),
    }
    state = load_module("_states/pfsense_user_cert.py", __salt__=salt)
    ret = state.present("alice")
    assert ret["result"] is False
    assert ret["comment"] == "boom"
