from pathlib import Path
from typing import Any

import pytest
from salt.exceptions import CommandExecutionError

import pfrest
import pfsense
import pfsense_local
from fake_pfrest import Collection, FakePfrest

KEY = "0123456789abcdef"


@pytest.fixture
def server() -> FakePfrest:
    return FakePfrest(
        [
            Collection("firewall/alias", "firewall/aliases"),
            Collection("services/dhcp_server/static_mapping", "services/dhcp_server/static_mappings", parented=True),
        ]
    )


@pytest.fixture
def client(server: FakePfrest) -> pfrest.PfrestClient:
    return pfrest.PfrestClient(api_key=KEY, session=server)


def _alias(name: str) -> dict[str, Any]:
    return {"name": name, "type": "host", "address": ["192.0.2.1"]}


def test_api_key_from_file(tmp_path: Path) -> None:
    path = tmp_path / "api.key"
    path.write_text(KEY + "\n")
    assert pfrest.read_api_key(str(path)) == KEY
    path.write_text("")
    with pytest.raises(pfrest.PfrestError, match="empty"):
        pfrest.read_api_key(str(path))


def test_error_envelope_without_secret(client: pfrest.PfrestClient) -> None:
    with pytest.raises(pfrest.PfrestError) as error:
        client.post("firewall/alias", {"name": "X", "type": "host", "secret_field": "s3cr3t"})
    assert error.value.code == 400
    assert error.value.response_id == "FIELD_UNKNOWN"
    assert "s3cr3t" not in str(error.value) and KEY not in str(error.value) and KEY not in repr(client)


def _id(client: pfrest.PfrestClient, name: str) -> Any:
    found = client.find_one("firewall/aliases", name=name)
    assert found is not None
    return found["id"]


def test_ids_shift_and_find_one_resolves_by_key(client: pfrest.PfrestClient, server: FakePfrest) -> None:
    for name in ("A", "B", "C"):
        client.post("firewall/alias", _alias(name))
    assert _id(client, "C") == 2
    client.delete("firewall/alias", _id(client, "A"))
    assert _id(client, "C") == 1
    assert client.find_one("firewall/aliases", name="A", allow_missing=True) is None
    with pytest.raises(pfrest.PfrestError, match="NOT_FOUND"):
        client.find_one("firewall/aliases", name="A")


def test_find_one_ambiguous(client: pfrest.PfrestClient) -> None:
    client.post("firewall/alias", _alias("A"))
    client.post("firewall/alias", _alias("A"))
    with pytest.raises(pfrest.PfrestError, match="AMBIGUOUS"):
        client.find_one("firewall/aliases", name="A")


def test_write_checked_lifecycle(client: pfrest.PfrestClient, server: FakePfrest) -> None:
    created = client.write_checked("POST", "firewall/alias", "firewall/aliases", {"name": "A"}, body=_alias("A"))
    assert created is not None and created["address"] == ["192.0.2.1"]
    client.post("firewall/alias", _alias("B"))
    updated = client.write_checked(
        "PATCH", "firewall/alias", "firewall/aliases", {"name": "B"}, body={"address": ["192.0.2.9"]}
    )
    assert updated is not None and updated["address"] == ["192.0.2.9"]
    assert client.write_checked("DELETE", "firewall/alias", "firewall/aliases", {"name": "A"}) is None
    assert [a["name"] for a in server.objects("firewall/alias")] == ["B"]


def test_parented_objects(client: pfrest.PfrestClient, server: FakePfrest) -> None:
    mapping = {"mac": "02:00:5e:00:53:01", "ipaddr": "192.168.1.10"}
    client.write_checked(
        "POST",
        "services/dhcp_server/static_mapping",
        "services/dhcp_server/static_mappings",
        {"mac": mapping["mac"]},
        body=mapping,
        parent_id="lan",
    )
    found = client.find_one("services/dhcp_server/static_mappings", parent_id="lan", mac=mapping["mac"])
    assert found is not None and found["parent_id"] == "lan"
    assert client.find("services/dhcp_server/static_mappings", parent_id="opt1", mac=mapping["mac"]) == []


def test_dry_run_validates_without_writing(server: FakePfrest) -> None:
    client = pfrest.PfrestClient(api_key=KEY, session=server, dry_run=True)
    assert client.write_checked("POST", "firewall/alias", "firewall/aliases", {"name": "A"}, body=_alias("A")) is None
    assert server.objects("firewall/alias") == []
    assert server.requests[0][2]["dry_run"] is True
    with pytest.raises(pfrest.PfrestError, match="FIELD_READ_ONLY"):
        pfrest.PfrestClient(api_key=KEY, session=FakePfrest([Collection("firewall/rule", "firewall/rules")])).post(
            "firewall/rule",
            {
                "type": "pass",
                "interface": ["lan"],
                "ipprotocol": "inet",
                "source": "any",
                "destination": "any",
                "tracker": 1,
            },
        )
    assert client.apply("firewall") is None


def test_apply_is_synchronous(client: pfrest.PfrestClient, server: FakePfrest) -> None:
    client.apply("firewall")
    assert server.applied == ["firewall/apply"]
    assert server.requests[-1] == ("POST", "firewall/apply", {"async": False})


def test_conflict_detected_inside_lock(client: pfrest.PfrestClient, server: FakePfrest, tmp_path: Path) -> None:
    lock = str(tmp_path / "lock")
    with pfrest.config_lock(client, lock):
        client.post("firewall/alias", _alias("A"))
        client.post("firewall/alias", _alias("B"))
        server.external_write()
        with pytest.raises(pfrest.PfrestConflict):
            client.post("firewall/alias", _alias("C"))
    assert client.expected_revision is None
    assert [a["name"] for a in server.objects("firewall/alias")] == ["A", "B"]


def test_get_backend() -> None:
    pillar = {"pfsense:api_backend": "pfrest", "pfsense:api_backend_overrides:pfsense_cron": "fauxapi"}

    def config_get(key: str, default: Any) -> Any:
        return pillar.get(key, default)

    assert pfsense.get_backend(config_get, "pfsense_alias") == "pfrest"
    assert pfsense.get_backend(config_get, "pfsense_cron") == "fauxapi"
    assert pfsense.get_backend(lambda key, default: default, "pfsense_alias") == "fauxapi"
    with pytest.raises(CommandExecutionError):
        pfsense.get_backend(lambda key, default: "rest", "pfsense_alias")


def test_webgui_base_url() -> None:
    assert pfsense_local.webgui_base_url({}) == "https://127.0.0.1:443"
    config = {"system": {"webgui": {"protocol": "https", "port": "8443"}}}
    assert pfsense_local.webgui_base_url(config) == "https://127.0.0.1:8443"
