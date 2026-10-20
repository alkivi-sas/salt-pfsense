"""pfrest implementation of pfsense_syslog_configuration (status/logs/settings, always applied)."""

from typing import Any

from salt.exceptions import CommandExecutionError

import pfrest

ENDPOINT = "status/logs/settings"


class NotCovered(CommandExecutionError):
    """The syslog key has no LogSettings field (it goes through config_path)."""


# config.xml syslog key -> LogSettings field, when the names differ
FIELDS = {
    "enable": "enableremotelogging",
    "ipproto": "ipprotocol",
    "reverse": "reverseorder",
}
INTEGERS = {"filterdescriptions", "logfilesize", "nentries", "rotatecount"}
BOOLEANS = {
    "auth",
    "dhcp",
    "disablelocallogging",
    "dpinger",
    "enableremotelogging",
    "filter",
    "hostapd",
    "logall",
    "logconfigchanges",
    "nologbogons",
    "nologdefaultblock",
    "nologdefaultpass",
    "nolognginx",
    "nologprivatenets",
    "ntpd",
    "portalauth",
    "ppp",
    "rawfilter",
    "resolver",
    "reverseorder",
    "routing",
    "system",
    "vpn",
}
# Stored as the string 'enabled' in config.xml instead of an empty flag
ENABLED_STRINGS = {"logconfigchanges"}
STRINGS = {"format", "ipprotocol", "logcompressiontype", "remoteserver", "remoteserver2", "remoteserver3", "sourceip"}


def field(name: str) -> str:
    """LogSettings field for a config.xml syslog key; raise when pfrest does not model it."""
    mapped = FIELDS.get(name, name)
    if mapped not in INTEGERS | BOOLEANS | STRINGS:
        raise NotCovered("syslog setting {0} is not covered by pfrest".format(name))
    return mapped


def get_setting(api: pfrest.PfrestClient, name: str) -> Any:
    """Value in the FauxAPI backend format: booleans for flags, strings otherwise, False when unset."""
    mapped = field(name)
    value = (api.get(ENDPOINT) or {}).get(mapped)
    if mapped in ENABLED_STRINGS:
        return "enabled" if value else False
    if mapped in BOOLEANS:
        return bool(value)
    if value is None:
        return False
    return str(value)


def _to_api(name: str, value: Any) -> Any:
    if name in ENABLED_STRINGS:
        return value in (True, "enabled")
    if name in BOOLEANS:
        return bool(value)
    if name in INTEGERS:
        return int(value)
    return str(value)


def set_setting(api: pfrest.PfrestClient, name: str, value: Any) -> bool:
    if get_setting(api, name) == value:
        return True
    mapped = field(name)
    api.patch(ENDPOINT, {mapped: _to_api(mapped, value)})
    return True
