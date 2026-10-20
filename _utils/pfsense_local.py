"""
Read the pfSense configuration locally, without any API.

The minion runs on the firewall: PHP loads config.xml with pfSense's own parser (list tags, empty
values), which gives exactly the structure FauxAPI's config_get returned.
"""

import json
import subprocess
from typing import Any

PHP_DUMP = 'require_once("config.inc"); global $config; echo json_encode($config);'


def read_config() -> dict[str, Any]:
    result = subprocess.run(["php", "-r", PHP_DUMP], capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        raise RuntimeError("unable to read config.xml: {0}".format(result.stderr.strip()))
    return json.loads(result.stdout)


def webgui_base_url(config: dict[str, Any]) -> str:
    """Local WebGUI URL, which also serves the REST API."""
    webgui = config.get("system", {}).get("webgui", {}) or {}
    protocol = webgui.get("protocol") or "https"
    port = webgui.get("port") or ("443" if protocol == "https" else "80")
    return "{0}://127.0.0.1:{1}".format(protocol, port)
