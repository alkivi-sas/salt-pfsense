from pathlib import Path

from conftest import Loader


def test_check_key_file_without_keys_reports_error(load_module: Loader, tmp_path: Path) -> None:
    keyfile = tmp_path / "keys"
    keyfile.write_text("not a key\n")
    context: dict[str, str] = {}
    module = load_module(
        "_modules/pfsense_ssh.py",
        __salt__={"cp.cache_file": lambda source, saltenv: str(keyfile)},
        __context__=context,
    )
    assert module.check_key_file("admin", "salt://keys") == {}
    assert "No keys detected" in context["ssh_auth.error"]
