"""Run the PHP helpers against stub pfSense includes (tests/php/stubs), when php is available."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
STUBS = Path(__file__).resolve().parent / "stubs"

pytestmark = pytest.mark.skipif(shutil.which("php") is None, reason="php is not installed")


class Php:
    def __init__(self, tmp_path: Path, config: dict[str, Any]) -> None:
        self.config_file = tmp_path / "config.json"
        self.calls_file = tmp_path / "calls.log"
        self.config_file.write_text(json.dumps(config))
        self.calls_file.write_text("")

    def run(self, helper: str, request: dict[str, Any]) -> subprocess.CompletedProcess[str]:
        env = dict(
            os.environ, SALT_PFSENSE_TEST_CONFIG=str(self.config_file), SALT_PFSENSE_TEST_CALLS=str(self.calls_file)
        )
        return subprocess.run(
            ["php", "-d", "include_path={0}".format(STUBS), str(ROOT / "helpers" / helper)],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    @property
    def config(self) -> Any:
        return json.loads(self.config_file.read_text())

    @property
    def calls(self) -> list[Any]:
        return [json.loads(line) for line in self.calls_file.read_text().splitlines()]


def test_config_path_set_get_delete(tmp_path: Path) -> None:
    php = Php(tmp_path, {"system": {"sshguard_whitelist": "192.0.2.0/24"}})
    result = php.run(
        "config_path.php",
        {
            "op": "set",
            "path": "system/sshguard_whitelist",
            "value": "192.0.2.0/24 198.51.100.0/24",
            "apply": ["filter_configure", "system_syslogd_start"],
        },
    )
    assert json.loads(result.stdout) == {"changed": True}
    assert php.config["system"]["sshguard_whitelist"] == "192.0.2.0/24 198.51.100.0/24"
    assert [call[0] for call in php.calls] == ["write_config", "filter_configure", "system_syslogd_start"]

    again = php.run(
        "config_path.php",
        {
            "op": "set",
            "path": "system/sshguard_whitelist",
            "value": "192.0.2.0/24 198.51.100.0/24",
            "apply": ["filter_configure"],
        },
    )
    assert json.loads(again.stdout) == {"changed": False}
    assert len(php.calls) == 3

    got = php.run("config_path.php", {"op": "get", "path": "system/sshguard_whitelist"})
    assert json.loads(got.stdout) == {"value": "192.0.2.0/24 198.51.100.0/24"}

    php.run("config_path.php", {"op": "delete", "path": "system/sshguard_whitelist"})
    assert "sshguard_whitelist" not in php.config["system"]


@pytest.mark.parametrize(
    "request_, message",
    [
        ({"op": "set", "path": "system/user", "value": []}, "not allowed"),
        ({"op": "set", "path": "system/use_if_pppoe", "value": "", "apply": ["reboot"]}, "apply action reboot"),
    ],
)
def test_config_path_refuses(tmp_path: Path, request_: dict[str, Any], message: str) -> None:
    php = Php(tmp_path, {"system": {}})
    result = php.run("config_path.php", request_)
    assert result.returncode == 1 and message in result.stderr
    assert php.calls == []


def test_restapi_bootstrap_is_idempotent(tmp_path: Path) -> None:
    config = {
        "system": {"user": [{"name": "admin", "uid": 0}], "group": [], "nextuid": 2000, "nextgid": 2000},
        "installedpackages": {"package": [{"name": "RESTAPI", "conf": {"auth_methods": "BasicAuth"}}]},
    }
    php = Php(tmp_path, config)
    request = {
        "username": "salt-api",
        "group": "salt-api",
        "privileges": ["api-v2-system-version-get"],
        "key_hash": "f" * 64,
        "hash_algo": "sha256",
        "length_bytes": 32,
        "descr": "salt-pfsense",
    }
    first = php.run("restapi_bootstrap.php", request)
    assert json.loads(first.stdout) == {"changed": True}, first.stderr
    assert "f" * 64 not in first.stdout
    conf = php.config["installedpackages"]["package"][0]["conf"]
    assert conf["auth_methods"] == "BasicAuth,KeyAuth"
    assert conf["keys"]["key"] == [
        {"username": "salt-api", "hash_algo": "sha256", "length_bytes": "32", "descr": "salt-pfsense", "hash": "f" * 64}
    ]
    users = php.config["system"]["user"]
    assert users[1]["name"] == "salt-api" and users[1]["uid"] == 2000
    assert php.config["system"]["group"][0] == {
        "name": "salt-api",
        "description": "salt-pfsense REST API",
        "scope": "local",
        "gid": 2000,
        "member": [2000],
        "priv": ["api-v2-system-version-get"],
    }

    second = php.run("restapi_bootstrap.php", request)
    assert json.loads(second.stdout) == {"changed": False}


def test_user_set_fields(tmp_path: Path) -> None:
    php = Php(tmp_path, {"system": {"user": [{"name": "ro.admin", "bcrypt-hash": "old"}]}})
    result = php.run("user_set_fields.php", {"name": "ro.admin", "fields": {"bcrypt-hash": "$2y$10$new"}})
    assert json.loads(result.stdout) == {"changed": True}
    assert php.config["system"]["user"][0]["bcrypt-hash"] == "$2y$10$new"
    assert ["local_user_set", ["ro.admin"]] in php.calls
    refused = php.run("user_set_fields.php", {"name": "ro.admin", "fields": {"priv": ["page-all"]}})
    assert refused.returncode == 1 and "not allowed" in refused.stderr
