from typing import Any

import pytest

from conftest import Loader

CONFIG = {"system": {"hostname": "fw", "user": [{"name": "admin", "bcrypt-hash": "x"}]}}


def _config_get(backend: str) -> Any:
    return lambda key, default: backend if key == "pfsense:api_backend" else default


def test_pfrest_backend_reads_config_locally(load_module: Loader, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module("_modules/pfsense_config.py", __salt__={"config.get": _config_get("pfrest")})
    monkeypatch.setattr(module.pfsense_local, "read_config", lambda: CONFIG)
    monkeypatch.setattr(module, "_get_client", lambda: pytest.fail("FauxAPI must not be called"))
    assert module.get("system:hostname") == "fw"
    assert module.get("system:user:0:bcrypt-hash") == "**REDACTED**"


def test_fauxapi_backend_unchanged(load_module: Loader, monkeypatch: pytest.MonkeyPatch) -> None:
    class Client:
        def config_get(self) -> dict[str, Any]:
            return CONFIG

    module = load_module("_modules/pfsense_config.py", __salt__={"config.get": _config_get("fauxapi")})
    monkeypatch.setattr(module, "_get_client", lambda: Client())
    assert module.get("system:hostname") == "fw"
