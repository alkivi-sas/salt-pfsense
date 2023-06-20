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
import binascii
import logging

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

def _get_client():
    return pfsense.FauxapiLib(debug=True)


def _sync_ha():
    cmd = ['/etc/rc.filter_synchronize']
    __salt__['cmd.run_all'](cmd, python_shell=False)


def list_hostnames():
    '''
    Return the alternatives hostnames of the webgui
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_althostnames.list_hostnames
    '''
    client = _get_client()
    config = client.config_get()

    if 'althostnames' not in config['system']['webgui']:
        return []
    else:
        return config['system']['webgui']['althostnames'].split(' ')


def has_hostname(hostname):
    '''
    Return true if the hostname is present in althostnames
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_althostnames.has_hostname test
    '''
    if hostname== '':
        raise SaltInvocationError('alias can not be an empty string')

    hostnames = list_hostnames()
    if hostname in hostnames:
        return True
    else:
        return False

def add_hostname(hostname):
    '''
    Add the entry to the list
    exist.
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_aliases.set_target alias target
    '''

    if hostname == '':
        raise SaltInvocationError('alias can not be an empty string')

    current_hostnames = list_hostnames()
    if hostname in current_hostnames:
        return True

    current_hostnames.append(hostname)

    client = _get_client()
    config = client.config_get()

    config['system']['webgui']['althostnames'] = ' '.join(current_hostnames)
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating alias')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating alias')
    _sync_ha()
    return True


def rm_hostname(hostname):
    '''
    Remove an entry from the aliases file
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_aliases.rm_alias alias
    '''
    current_hostnames = list_hostnames()
    if hostname not in current_hostnames:
        return True

    client = _get_client()
    config = client.config_get()

    new_hostnames = []
    for current_hostname in current_hostnames:
        if current_hostname == hostname:
            continue
        new_hostnames.append(current_hostname)

    config['system']['webgui']['althostnames'] = ' '.join(new_hostnames)
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating alias')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating alias')
    _sync_ha()
    return True
