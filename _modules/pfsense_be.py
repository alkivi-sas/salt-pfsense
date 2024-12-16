# -*- coding: utf-8 -*-
"""
Module for running pfsense module via fauxapi
"""
from __future__ import absolute_import

# Import Python libs
import os
import re
import base64
import hashlib
import time
import binascii
import logging
import json

# Import Salt libs
import salt.utils.files
import salt.utils.stringutils
import pfsense
from salt.exceptions import (
    CommandExecutionError,
    SaltInvocationError,
)

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def list_be():
    """Return array of boot environnements."""
    cmd = ['php', '/scripts/manage_bootenv.php', '--list']
    result = __salt__['cmd.run_all'](cmd,
                                     python_shell=False)
    if result['retcode'] != 0:
        raise CommandExecutionError(result['stdout'])
    return json.loads(result['stdout'])


def delete_be(name):
    all_be = list_be()
    wanted_be = list(filter(lambda x: x["name"] == name, all_be))
    if len(wanted_be) != 1:
        raise CommandExecutionError("Unable to find a be with name={0}".format(name))
    wanted_be = wanted_be[0]
    if wanted_be["status"] != "Inactive":
        raise CommandExecutionError("Unable to delete be {0} because status is {1}".format(name, wanted_be["status"]))

    cmd = ['php', '/scripts/manage_bootenv.php', '--delete={0}'.format(name)]
    result = __salt__['cmd.run_all'](cmd,
                                     python_shell=False)
    if result['retcode'] != 0:
        raise CommandExecutionError(result['stdout'])
    return True
    
def delete_be_for_version(version):
    all_be = list_be()
    wanted_be = list(filter(lambda x: x["version"] == version, all_be))

    deleted = []
    errors = []
    for be in wanted_be:
        name = be["name"]
        if be["status"] != "Inactive":
            logger.warning("No deleting boot environnement {0} because is not inactive".format(name))
            continue
        cmd = ['php', '/scripts/manage_bootenv.php', '--delete={0}'.format(name)]
        result = __salt__['cmd.run_all'](cmd,
                                     python_shell=False)
        if result['retcode'] != 0:
            errors.append(name)
        else:
            deleted.append(name)

    return {"deleted": deleted, "errors": errors}
