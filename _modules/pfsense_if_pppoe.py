# -*- coding: utf-8 -*-
"""
Module to manage <use_if_pppoe></use_if_pppoe> flag in pfSense system config.

Exposes two idempotent functions:
- enable(reboot=True): ensure key exists under config["system"]
- disable(reboot=True): ensure key is absent

If reboot is True and a change was applied, the node will be rebooted with a 5s delay.
"""
from __future__ import absolute_import

# Import Python libs
import os
import logging

# Import Salt libs
import pfsense
from salt.exceptions import (
    CommandExecutionError,
)

logger = logging.getLogger(__name__)


def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False


def _get_client():
    # Use singleton to reuse session/config
    return pfsense.FauxapiLib.get_singleton(debug=True)


def _reboot_if_requested(reboot, changed):
    if reboot and changed:
        __salt__['cmd.run']('shutdown -r +1')


def _set_use_if_pppoe(present, reboot=True):
    """
    Ensure the <use_if_pppoe> flag presence (present=True) or absence (present=False)
    under config['system'].
    """
    client = _get_client()
    config = client.config_get()

    if 'system' not in config:
        raise CommandExecutionError('config is not valid: key {0} not found'.format('system'))

    system_cfg = config['system']

    currently_present = 'use_if_pppoe' in system_cfg
    if currently_present == present:
        # No change required
        return True

    if present:
        # Boolean-like flags in pfSense XML are represented as empty string values
        system_cfg['use_if_pppoe'] = ''
    else:
        if 'use_if_pppoe' in system_cfg:
            del system_cfg['use_if_pppoe']

    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating use_if_pppoe flag')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating use_if_pppoe flag')

    _reboot_if_requested(reboot, True)
    return True


def enable(reboot=True):
    """
    Ensure <use_if_pppoe></use_if_pppoe> exists under system configuration.

    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_if_pppoe.enable
        salt '*' pfsense_if_pppoe.enable reboot=False
    """
    return _set_use_if_pppoe(True, reboot=reboot)


def disable(reboot=True):
    """
    Ensure <use_if_pppoe></use_if_pppoe> is absent from system configuration.

    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_if_pppoe.disable
        salt '*' pfsense_if_pppoe.disable reboot=False
    """
    return _set_use_if_pppoe(False, reboot=reboot)


