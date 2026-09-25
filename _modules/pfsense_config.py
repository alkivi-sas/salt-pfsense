# -*- coding: utf-8 -*-
"""
Read-only browsing of the pfSense config (config.xml) via FauxAPI.

Every public function takes a single optional ``key`` argument so it can be
exposed through a gateway that only forwards ``tgt`` and ``key`` (the Alkivi
MCP salt provider). ``key`` is a colon separated path, exactly like
``pillar.get``; list items are addressed by their index::

    system:hostname
    interfaces:wan:ipaddr
    filter:rule:0:descr
    installedpackages:wireguard:tunnels:item

A ``*`` segment stands for every child of a list (or of a dict), so one call
returns a column instead of every record -- handy on a firewall with hundreds
of users or rules. The result is ``{index: value}`` (``{key: value}`` for a
dict), so two columns of the same list can be joined on the index::

    system:user:*:name          # {"0": "a.breton", "1": ...}
    system:user:*:cert          # {"0": ["5e6f8a9879121"], ...}
    filter:rule:*:descr         # every rule description
    nat:rule:*:destination      # every port forward destination

Children that lack the rest of the path are skipped: ``system:user:*:cert``
only holds the users that have a certificate.

Sensitive values (passwords, hashes, private keys, PSK, API secrets...) are
masked by default. Pass ``redact=False`` from the CLI to see them.
"""
from __future__ import absolute_import

# Import Python libs
import os
import re
import logging

# Import Salt libs
import pfsense
from salt.exceptions import SaltInvocationError

logger = logging.getLogger(__name__)

__virtualname__ = "pfsense_config"

DELIMITER = ":"
REDACTED = "**REDACTED**"

# Key names (case insensitive) whose value is always masked.
SENSITIVE_KEYS = frozenset(
    [
        "password",
        "passwd",
        "bcrypt-hash",
        "md5-hash",
        "sha512-hash",
        "nt-hash",
        "prv",
        "privatekey",
        "privkey",
        "presharedkey",
        "pre-shared-key",
        "psk",
        "ipsecpsk",
        "secret",
        "apisecret",
        "apikey",
        "authkey",
        "authorizedkeys",
        "tls",
        "tlskey",
        "shared_key",
        "ca_key",
        "cert_key",
        "radius_secret",
        "ldap_bindpw",
        "snmpcommunity",
        "rocommunity",
        "rwcommunity",
        "pass",
    ]
)

# Key names matching one of these patterns are masked as well.
SENSITIVE_PATTERNS = (
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"passwd", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"priv(ate)?[-_]?key", re.IGNORECASE),
    re.compile(r"(^|[-_])prv([-_]|$)", re.IGNORECASE),
    re.compile(r"[-_]hash$", re.IGNORECASE),
    re.compile(r"community$", re.IGNORECASE),
)


def __virtual__():
    if os.path.isfile("/etc/pf.os"):
        return __virtualname__
    return (False, "pfsense_config: not a pfSense system")


def _get_client():
    return pfsense.FauxapiLib(debug=True)


def _get_config():
    return _get_client().config_get()


def _is_sensitive(name):
    lowered = str(name).lower()
    if lowered in SENSITIVE_KEYS:
        return True
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(lowered):
            return True
    return False


def _redact(data, parent_key=None):
    """Return a copy of ``data`` with sensitive values masked."""
    if parent_key is not None and _is_sensitive(parent_key):
        return REDACTED
    if isinstance(data, dict):
        return dict((k, _redact(v, k)) for k, v in data.items())
    if isinstance(data, list):
        return [_redact(v, parent_key) for v in data]
    return data


def _split(key, delimiter=DELIMITER):
    if key is None:
        return []
    if isinstance(key, (list, tuple)):
        return [str(k) for k in key]
    key = str(key).strip()
    if key in ("", delimiter):
        return []
    return [part for part in key.split(delimiter) if part != ""]


WILDCARD = "*"


def _traverse(config, parts):
    """Walk ``config`` following ``parts``.

    Returns ``(found, value)``; when not found, ``value`` is the last valid path.
    A ``*`` part maps the rest of the path over every child of the node.
    """
    node = config
    walked = []
    for position, part in enumerate(parts):
        if part == WILDCARD:
            rest = parts[position + 1:]
            if isinstance(node, list):
                node = dict((str(i), child) for i, child in enumerate(node))
            if isinstance(node, dict):
                items = [(k, _traverse(v, rest)) for k, v in node.items()]
                return True, dict((k, value) for k, (found, value) in items if found)
            return False, DELIMITER.join(walked) or "<root>"
        if isinstance(node, dict):
            if part in node:
                node = node[part]
            else:
                return False, DELIMITER.join(walked) or "<root>"
        elif isinstance(node, list):
            try:
                index = int(part)
                node = node[index]
            except (ValueError, IndexError):
                return False, DELIMITER.join(walked) or "<root>"
        else:
            return False, DELIMITER.join(walked) or "<root>"
        walked.append(part)
    return True, node


def _lookup(key, delimiter=DELIMITER, redact=False):
    """Return the node at ``key`` or raise; masked first when ``redact``."""
    config = _get_config()
    if redact:
        # Mask the whole tree before walking it: a ``*`` segment can end a path
        # below a sensitive key (``...:authorizedkeys:*``), where the last part
        # alone no longer says the values are secret.
        config = _redact(config)
    parts = _split(key, delimiter)
    found, value = _traverse(config, parts)
    if not found:
        raise SaltInvocationError(
            "key '{0}' not found in config (last valid node: {1})".format(
                delimiter.join(parts), value
            )
        )
    return value


def _describe(value):
    """Short type description used by :func:`tree`."""
    if isinstance(value, dict):
        return "dict[{0}]".format(len(value))
    if isinstance(value, list):
        return "list[{0}]".format(len(value))
    if value is None or value == "":
        return "empty"
    return type(value).__name__


def keys(key=None, delimiter=DELIMITER):
    """
    Return the keys available under ``key`` (top level when omitted).

    For a dict the result is the sorted list of its keys. For a list it is
    the list of indexes as strings, so they can be reused directly in a path.
    A scalar has no children and returns an empty list.

    CLI Example:

    .. code-block:: bash

        salt 'gateway.noza' pfsense_config.keys
        salt 'gateway.noza' pfsense_config.keys interfaces
        salt 'gateway.noza' pfsense_config.keys filter:rule
    """
    value = _lookup(key, delimiter)
    if isinstance(value, dict):
        return sorted(value.keys())
    if isinstance(value, list):
        return [str(i) for i in range(len(value))]
    return []


def get(key=None, delimiter=DELIMITER, redact=True):
    """
    Return the data stored under ``key`` (whole config when omitted).

    Sensitive values are masked unless ``redact=False``.

    CLI Example:

    .. code-block:: bash

        salt 'gateway.noza' pfsense_config.get system:hostname
        salt 'gateway.noza' pfsense_config.get interfaces:wan
        salt 'gateway.noza' pfsense_config.get filter:rule:0
        salt 'gateway.noza' pfsense_config.get 'system:user:*:name'
        salt 'gateway.noza' pfsense_config.get system:user redact=False
    """
    return _lookup(key, delimiter, redact=redact)


def tree(key=None, delimiter=DELIMITER):
    """
    Return the shape of the node at ``key``: each child with its type and
    size, without the values. Cheap way to decide where to descend next.

    CLI Example:

    .. code-block:: bash

        salt 'gateway.noza' pfsense_config.tree
        salt 'gateway.noza' pfsense_config.tree installedpackages
    """
    value = _lookup(key, delimiter)
    if isinstance(value, dict):
        return dict((k, _describe(v)) for k, v in value.items())
    if isinstance(value, list):
        return dict((str(i), _describe(v)) for i, v in enumerate(value))
    return _describe(value)


def search(key, delimiter=DELIMITER, redact=True, limit=200):
    """
    Return every path whose key name or scalar value contains ``key``
    (case insensitive). Result is ``{path: value}``.

    Handy to find where an IP, a hostname or an option lives in the config.

    CLI Example:

    .. code-block:: bash

        salt 'gateway.noza' pfsense_config.search 192.168.10.1
        salt 'gateway.noza' pfsense_config.search wireguard
    """
    if key is None or str(key) == "":
        raise SaltInvocationError("search needs a non empty key")

    needle = str(key).lower()
    config = _get_config()
    if redact:
        config = _redact(config)

    ret = {}

    def _walk(node, path):
        if len(ret) >= limit:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                sub = path + [str(k)]
                if needle in str(k).lower():
                    if isinstance(v, (dict, list)):
                        ret[delimiter.join(sub)] = _describe(v)
                    else:
                        ret[delimiter.join(sub)] = v
                _walk(v, sub)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                _walk(v, path + [str(i)])
        else:
            if node is not None and needle in str(node).lower():
                ret[delimiter.join(path)] = node

    _walk(config, [])
    return ret
