"""
pfrest implementation of the pfsense_certificate writes (system/certificate, system/certificate/generate,
system/crl/revoked_certificate).

Reads stay on the local config.xml: private keys are masked by pfrest and callers rely on the
config.xml refids and indexes. config.xml stores crt/prv base64 encoded, pfrest takes PEM.
The subject of generated user certificates comes from the pillar (pfsense:pki:dn) instead of the
values hard coded in cert_create.php; the CA serial is handled by pfSense.
"""

import base64
from typing import Any

import pfrest

CERT = "system/certificate"
CERTS = "system/certificates"
GENERATE = "system/certificate/generate"
REVOKED = "system/crl/revoked_certificate"

DN_FIELDS = ("country", "state", "city", "organization", "organizationalunit")
USER_CERT = {"keytype": "RSA", "keylen": 2048, "digest_alg": "sha256", "lifetime": 3650, "type": "user"}


def _pem(value: str) -> str:
    return base64.b64decode(value).decode("utf-8")


def generate_user_cert(api: pfrest.PfrestClient, username: str, caref: str, dn: dict[str, str]) -> dict[str, Any]:
    body: dict[str, Any] = dict(USER_CERT, descr=username, caref=caref, dn_commonname=username)
    body.update({"dn_" + key: dn[key] for key in DN_FIELDS if dn.get(key)})
    created = api.post(GENERATE, body) or {}
    # Never return the private key
    return {"refid": created.get("refid"), "descr": username, "caref": caref, "type": "user"}


def import_cert(api: pfrest.PfrestClient, descr: str, crt: str, prv: str, cert_type: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {"descr": descr, "crt": _pem(crt), "prv": _pem(prv)}
    if cert_type:
        body["type"] = cert_type
    created = api.post(CERT, body) or {}
    return {"refid": created.get("refid"), "descr": descr, "type": cert_type}


def patch_cert(api: pfrest.PfrestClient, refid: str, crt: str | None, prv: str | None, descr: str | None) -> None:
    body: dict[str, Any] = {}
    if crt is not None:
        body["crt"] = _pem(crt)
    if prv is not None:
        body["prv"] = _pem(prv)
    if descr is not None:
        body["descr"] = str(descr)
    api.write_checked("PATCH", CERT, CERTS, {"refid": refid}, body=body)


def remove_cert(api: pfrest.PfrestClient, refid: str) -> None:
    api.write_checked("DELETE", CERT, CERTS, {"refid": refid})


def revoke(api: pfrest.PfrestClient, crl_index: int, certref: str, reason: int) -> None:
    """Revoke certref in the CRL at crl_index (internal CRL); pfrest regenerates it and refreshes OpenVPN."""
    api.post(REVOKED, {"parent_id": crl_index, "certref": certref, "reason": int(reason)})
