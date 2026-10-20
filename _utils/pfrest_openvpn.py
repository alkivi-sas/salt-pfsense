"""
pfrest implementation of the OpenVPN client export (vpn/openvpn/client_export, needs the
openvpn-client-export package). It replaces the per pfSense version export_openvpn_config.php helpers.

The export uses the default export configuration of the server (installedpackages/vpn_openvpn_export,
whose index is the export config id) and overrides the options the helpers set.
"""

from typing import Any

from salt.exceptions import CommandExecutionError

import pfrest

EXPORT = "vpn/openvpn/client_export"
EXPORT_DIR = "/tmp"
USEADDR = ("serveraddr", "servermagic", "servermagichost", "serverhostname")
# Options of the helpers (helpers-23XXRELEASE/export_openvpn_config.php)
OPTIONS = {"verifyservercn": "auto", "legacy": False, "silent": True, "bindmode": "nobind", "p12encryption": "high"}
EXTENSIONS = {
    "confzip": "zip",
    "visc": "zip",
    "confinline": "ovpn",
    "confinlinedroid": "ovpn",
    "confinlineconnect": "ovpn",
    "confinlinevisc": "ovpn",
}


def indexes(config: dict[str, Any], vpnid: str) -> tuple[int, int]:
    """(OpenVPN server id, export config id) of vpnid in config.xml."""
    servers = (config.get("openvpn") or {}).get("openvpn-server") or []
    servers = [servers] if isinstance(servers, dict) else servers
    server = [i for i, s in enumerate(servers) if str(s.get("vpnid")) == str(vpnid)]
    export = ((config.get("installedpackages") or {}).get("vpn_openvpn_export") or {}).get("serverconfig") or {}
    items = export.get("item") or [] if isinstance(export, dict) else []
    items = [items] if isinstance(items, dict) else items
    export_ids = [i for i, item in enumerate(items) if str(item.get("server")) == str(vpnid)]
    if not server or not export_ids:
        raise CommandExecutionError("no OpenVPN server or export configuration for vpnid {0}".format(vpnid))
    return server[0], export_ids[0]


def export(
    api: pfrest.PfrestClient,
    server_id: int,
    export_id: int,
    username: str,
    certref: str,
    addr: str,
    conf_type: str,
) -> tuple[str | None, bytes]:
    body: dict[str, Any] = dict(
        OPTIONS, id=export_id, server=server_id, type=conf_type, username=username, certref=certref
    )
    if addr in USEADDR:
        body["useaddr"] = addr
    else:
        body.update(useaddr="other", useaddr_hostname=addr)
    return api.download(EXPORT, body)


def default_filename(username: str, conf_type: str) -> str:
    extension = EXTENSIONS.get(conf_type, "exe" if conf_type.startswith("inst-") else "bin")
    return "{0}-{1}.{2}".format(username, conf_type, extension)
