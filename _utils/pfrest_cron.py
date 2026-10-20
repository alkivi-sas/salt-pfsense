"""
pfrest implementation of the pfsense_cron writes (services/cron/job, requires pfSense-pkg-Cron).

Reads stay on the local config.xml: the module's identifier (custom field or hash of the entry) keeps
its meaning. pfrest does not model the custom identifier field, so jobs are resolved by command.
"""

from typing import Any

import pfrest

ONE = "services/cron/job"
MANY = "services/cron/jobs"
FIELDS = ("minute", "hour", "mday", "month", "wday", "who", "command")


def _body(cron: dict[str, Any]) -> dict[str, Any]:
    return {field: str(cron[field]) for field in FIELDS if cron.get(field) is not None}


def add_cron(api: pfrest.PfrestClient, cron: dict[str, Any]) -> None:
    api.write_checked("POST", ONE, MANY, {"command": cron["command"]}, body=_body(cron))


def manage_cron(api: pfrest.PfrestClient, command: str, cron: dict[str, Any]) -> None:
    """Update the job currently running command with the fields of cron (which may change the command)."""
    current = api.find_one(MANY, command=command)
    assert current is not None
    api.patch(ONE, dict(_body(cron), id=current["id"]))


def remove_cron(api: pfrest.PfrestClient, command: str) -> None:
    api.write_checked("DELETE", ONE, MANY, {"command": command})
