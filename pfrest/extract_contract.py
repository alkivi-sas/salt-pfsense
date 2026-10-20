"""Extract a compact contract (methods, parameters, body fields) from a pfrest openapi.json.

Usage: python pfrest/extract_contract.py openapi.json v2.10.2 pfrest/contract/v2.10.2.json
The full schema is published with each pfrest release:
https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/download/<version>/openapi.json
"""

import json
import sys
from pathlib import Path
from typing import Any

# Endpoint families used by the Salt modules (docs/migration/coverage.md)
PREFIXES = (
    "/api/v2/auth/key",
    "/api/v2/diagnostics/config_history",
    "/api/v2/firewall/alias",
    "/api/v2/firewall/apply",
    "/api/v2/firewall/nat/port_forward",
    "/api/v2/firewall/rule",
    "/api/v2/interface",
    "/api/v2/routing/apply",
    "/api/v2/routing/gateway",
    "/api/v2/services/cron/job",
    "/api/v2/services/dhcp_server",
    "/api/v2/services/ssh",
    "/api/v2/status/gateways",
    "/api/v2/status/logs/settings",
    "/api/v2/system/certificate",
    "/api/v2/system/crl",
    "/api/v2/system/dns",
    "/api/v2/system/hostname",
    "/api/v2/system/package",
    "/api/v2/system/restapi",
    "/api/v2/system/version",
    "/api/v2/system/webgui/settings",
    "/api/v2/user",
    "/api/v2/vpn/openvpn/client_export",
    "/api/v2/vpn/openvpn/server",
    "/api/v2/vpn/wireguard",
)
FIELD_KEYS = ("type", "enum", "nullable", "readOnly", "writeOnly", "default")


def _schema_name(body: dict[str, Any]) -> tuple[str | None, list[str]]:
    schema = body.get("content", {}).get("application/json", {}).get("schema", {})
    name, required = None, []
    for part in schema.get("allOf", [schema]):
        if "$ref" in part:
            name = part["$ref"].rsplit("/", 1)[-1]
        required.extend(part.get("required", []))
    return name, sorted(required)


def extract(openapi: dict[str, Any], version: str) -> dict[str, Any]:
    schemas = openapi["components"]["schemas"]
    models: dict[str, Any] = {}
    endpoints: dict[str, Any] = {}
    for path, operations in sorted(openapi["paths"].items()):
        if not path.startswith(PREFIXES):
            continue
        endpoint: dict[str, Any] = {}
        for method, operation in operations.items():
            entry: dict[str, Any] = {"parameters": sorted(p["name"] for p in operation.get("parameters", []))}
            if "requestBody" in operation:
                model, required = _schema_name(operation["requestBody"])
                entry["model"], entry["required"] = model, required
                if model and model not in models:
                    properties = schemas[model].get("properties", {})
                    models[model] = {
                        field: {k: v for k, v in spec.items() if k in FIELD_KEYS} for field, spec in properties.items()
                    }
            endpoint[method] = entry
        endpoints[path[len("/api/v2/") :]] = endpoint
    return {"version": version, "endpoints": endpoints, "models": models}


def main(argv: list[str]) -> int:
    source, version, target = Path(argv[1]), argv[2], Path(argv[3])
    contract = extract(json.loads(source.read_text()), version)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(contract, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
