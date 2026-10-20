from typing import Any, Callable

from conftest import FakeFauxapi, Loader


def test_utils_importable(load_module: Loader) -> None:
    module = load_module("_utils/pfsense.py")
    assert hasattr(module, "FauxapiLib")


def test_module_gets_dunders(load_module: Loader) -> None:
    module = load_module("_modules/pfsense_alias.py", __salt__={"cmd.run_all": print})
    assert module.__salt__["cmd.run_all"] is print
    assert module.__opts__ == {"test": False}


def test_fake_fauxapi_patch_merges(fake_fauxapi: Callable[[dict[str, Any]], FakeFauxapi]) -> None:
    client = fake_fauxapi({"system": {"hostname": "fw", "dnsserver": ["1.1.1.1"]}})
    client.config_patch({"system": {"dnsserver": ["9.9.9.9"]}})
    assert client.config_get("system") == {"hostname": "fw", "dnsserver": ["9.9.9.9"]}
