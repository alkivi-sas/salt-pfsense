import hashlib

import pytest

import pfrest_lifecycle as lifecycle
from fake_pfrest import CONTRACT


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("26.07-RELEASE\n", ("26.07", "Plus")),
        ("26.03.1-RELEASE", ("26.03.1", "Plus")),
        ("2.8.1-RELEASE", ("2.8.1", "CE")),
        ("2.9.0-RELEASE", ("2.9.0", "CE")),
    ],
)
def test_parse_version(raw: str, expected: tuple[str, str]) -> None:
    assert lifecycle.parse_version(raw) == expected


def test_supported_bases() -> None:
    assert lifecycle.is_supported("26.07")
    assert lifecycle.is_supported("2.8.1")
    assert not lifecycle.is_supported("2.7.2")
    assert not lifecycle.is_supported("25.11")


def test_install_command_bypasses_plus_repositories() -> None:
    url = "https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/download/v2.10.2/pfSense-26.07-pkg-RESTAPI.pkg"
    assert lifecycle.install_command("26.07", "Plus") == ["pkg-static", "-C", "/dev/null", "add", url]
    assert lifecycle.install_command("2.8.1", "CE")[:2] == ["pkg-static", "add"]


def test_package_version() -> None:
    assert lifecycle.package_version("v2.10.2") == "2.10_2"


def test_every_used_endpoint_exists_in_contract() -> None:
    for endpoint, methods in lifecycle.ENDPOINTS.items():
        assert endpoint in CONTRACT["endpoints"], endpoint
        for method in methods:
            assert method in CONTRACT["endpoints"][endpoint], (endpoint, method)


def test_privileges_least_privilege() -> None:
    privileges = lifecycle.privileges()
    assert "api-v2-firewall-nat-port-forward-patch" in privileges
    assert not any("command-prompt" in p for p in privileges)
    assert "page-all" not in privileges


def test_key_hash() -> None:
    assert lifecycle.key_hash("abcd") == hashlib.sha256(b"abcd").hexdigest()


def test_default_settings_are_contract_fields() -> None:
    fields = CONTRACT["models"]["RESTAPISettings"]
    assert set(lifecycle.DEFAULT_SETTINGS) <= set(fields)
