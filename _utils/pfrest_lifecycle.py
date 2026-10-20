"""
Lifecycle of the pfSense-pkg-RESTAPI package: pinned version, compatibility, install command,
least privilege list of the dedicated API user, key hash. See docs/migration/restapi.md (lot 3).
"""

import hashlib
import re

PFREST_VERSION = "v2.10.2"
PACKAGE = "pfSense-pkg-RESTAPI"
RELEASE_URL = "https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/download/{version}/pfSense-{base}-pkg-RESTAPI.pkg"

# pfSense bases with a package asset in PFREST_VERSION (docs/migration/versions.md)
SUPPORTED_BASES = {
    PFREST_VERSION: ("2.8.1", "2.9.0", "25.11.1", "26.03", "26.03.1", "26.07"),
}

API_USER = "salt-api"
API_GROUP = "salt-api"
KEY_DESCR = "salt-pfsense"
KEY_HASH_ALGO = "sha256"
KEY_LENGTH_BYTES = 32

# Settings managed declaratively (RESTAPISettings fields of the contract)
DEFAULT_SETTINGS = {
    "enabled": True,
    "auth_methods": ["KeyAuth"],
    "read_only": False,
    "keep_backup": True,
    "login_protection": True,
    "expose_sensitive_fields": False,
    "ha_sync": False,
    "hateoas": False,
    # Modules use the internal interface ids (wan, lan, optN), not the descriptions
    "represent_interfaces_as": "id",
}

# Endpoints and methods used by the modules: source of the least privilege list.
# diagnostics/command_prompt is never granted (unescaped shell execution).
ENDPOINTS: dict[str, tuple[str, ...]] = {
    "diagnostics/config_history/revisions": ("get",),
    "firewall/alias": ("get", "post", "patch", "delete"),
    "firewall/aliases": ("get",),
    "firewall/apply": ("get", "post"),
    "firewall/nat/port_forward": ("get", "post", "patch", "delete"),
    "firewall/nat/port_forwards": ("get",),
    "firewall/rule": ("get", "post", "patch", "delete"),
    "firewall/rules": ("get",),
    "interface": ("get", "post", "patch", "delete"),
    "interface/apply": ("get", "post"),
    "interface/vlan": ("get", "post", "patch", "delete"),
    "interface/vlans": ("get",),
    "interfaces": ("get",),
    "routing/apply": ("get", "post"),
    "routing/gateways": ("get",),
    "services/cron/job": ("get", "post", "patch", "delete"),
    "services/cron/jobs": ("get",),
    "services/dhcp_server": ("get", "patch"),
    "services/dhcp_server/apply": ("get", "post"),
    "services/dhcp_server/backend": ("patch",),
    "services/dhcp_server/custom_option": ("get", "delete"),
    "services/dhcp_server/custom_options": ("get",),
    "services/dhcp_server/static_mapping": ("get", "post", "patch", "delete"),
    "services/dhcp_server/static_mappings": ("get",),
    "services/dhcp_servers": ("get",),
    "status/gateways": ("get",),
    "status/logs/settings": ("get", "patch"),
    "system/certificate": ("get", "post", "patch", "delete"),
    "system/certificate/generate": ("post",),
    "system/certificate_authorities": ("get",),
    "system/certificate_authority": ("get",),
    "system/certificates": ("get",),
    "system/crl": ("get",),
    "system/crl/revoked_certificate": ("get", "post", "delete"),
    "system/crls": ("get",),
    "system/dns": ("get", "patch"),
    "system/package": ("get", "post"),
    "system/packages": ("get",),
    "system/restapi/access_list": ("get",),
    "system/restapi/access_list/entry": ("get", "post", "patch", "delete"),
    "system/restapi/settings": ("get", "patch"),
    "system/version": ("get",),
    "system/webgui/settings": ("get", "patch"),
    "user": ("get", "post", "patch", "delete"),
    "user/group": ("get", "post", "patch", "delete"),
    "user/groups": ("get",),
    "users": ("get",),
    "vpn/openvpn/client_export": ("post",),
    "vpn/openvpn/server": ("get",),
    "vpn/openvpn/servers": ("get",),
    "vpn/wireguard/apply": ("get", "post"),
    "vpn/wireguard/peer": ("get", "post", "patch", "delete"),
    "vpn/wireguard/peers": ("get",),
    "vpn/wireguard/tunnel": ("get",),
    "vpn/wireguard/tunnels": ("get",),
}

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)+)")


def parse_version(raw: str) -> tuple[str, str]:
    """'26.07-RELEASE' -> ('26.07', 'Plus'), '2.8.1-RELEASE' -> ('2.8.1', 'CE')."""
    match = _VERSION_RE.match(raw.strip())
    if not match:
        raise ValueError("unexpected pfSense version {0!r}".format(raw))
    base = match.group(1)
    return base, ("CE" if int(base.split(".")[0]) < 20 else "Plus")


def is_supported(base: str, version: str = PFREST_VERSION) -> bool:
    return base in SUPPORTED_BASES.get(version, ())


def asset_url(base: str, version: str = PFREST_VERSION) -> str:
    return RELEASE_URL.format(version=version, base=base)


def install_command(base: str, edition: str, version: str = PFREST_VERSION) -> list[str]:
    # Plus points pkg to Netgate signed repositories: bypass them for this unofficial package
    options = ["-C", "/dev/null"] if edition == "Plus" else []
    return ["pkg-static"] + options + ["add", asset_url(base, version)]


def package_version(tag: str) -> str:
    """Release tag to FreeBSD package version: 'v2.10.2' -> '2.10_2' (verified on 2.10.2 only)."""
    major, minor, patch = tag.lstrip("v").split(".")
    return "{0}.{1}_{2}".format(major, minor, patch) if patch != "0" else "{0}.{1}".format(major, minor)


def privilege(endpoint: str, method: str) -> str:
    """pfrest privilege name: firewall/nat/port_forward + patch -> api-v2-firewall-nat-port-forward-patch."""
    return "api-v2-{0}-{1}".format(endpoint.replace("/", "-").replace("_", "-"), method)


def privileges() -> list[str]:
    return sorted(privilege(endpoint, method) for endpoint, methods in ENDPOINTS.items() for method in methods)


def key_hash(key: str, algo: str = KEY_HASH_ALGO) -> str:
    """Hash stored by pfrest for an API key: hash(algo, key) on the hexadecimal key string."""
    return hashlib.new(algo, key.encode("utf-8")).hexdigest()
