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
import pfrest_module
import pfsense_config_path
import pfsense_local
from salt.exceptions import (
    CommandExecutionError,
    SaltInvocationError,
)

try:
    from ipaddress import IPv4Interface
except ImportError:
    from salt.ext.ipaddress import IPv4Interface

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)


def _pfrest():
    return pfrest_module.enabled(__salt__, 'pfsense_sshguard_whitelist')


def _config():
    if _pfrest():
        return pfsense_local.read_config()
    return _get_client().config_get()


def _check_ip(ip):
    interface = IPv4Interface(ip)
    real_ip = interface.network.network_address._explode_shorthand_ip_string()
    subnet_mask = interface._prefixlen
    return '{0}/{1}'.format(real_ip, subnet_mask)


def list_ips():
    '''
    Return the list of whitelist ips of sshguard
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_sshguard_whitelist.list_ips
    '''
    config = _config()

    if 'sshguard_whitelist' not in config['system']:
        return []
    else:
        return config['system']['sshguard_whitelist'].split(' ')


def has_ip(ip):
    '''
    Return true if the ip is present in sshguard_whitelist
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_sshguard_whitelist.has_ip test
    '''
    ip = _check_ip(ip)

    ips = list_ips()
    if ip in ips:
        return True
    else:
        return False

def add_ip(ip):
    '''
    Add the entry to the list
    exist.
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_aliases.set_target alias target
    '''

    ip = _check_ip(ip)

    current_ips = list_ips()
    if ip in current_ips:
        return True

    current_ips.append(ip)

    if _pfrest():
        # Same apply as helpers/sshguard_whitelist.php
        with pfrest_module.session(__salt__, __opts__, ha_sync=False):
            pfsense_config_path.set_path(__salt__, 'system/sshguard_whitelist', ' '.join(current_ips),
                                         apply=['filter_configure', 'system_syslogd_start'], test=__opts__.get('test', False))
        return True

    client = _get_client()
    config = client.config_get()

    config['system']['sshguard_whitelist'] = ' '.join(current_ips)
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating alias')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating alias')

    cmd = ['php', '/opt/helpers/sshguard_whitelist.php']

    result = __salt__['cmd.run_all'](cmd,
                                     python_shell=False)

    if result['retcode'] != 0:
        raise CommandExecutionError(result['stdout'])
    return True


def rm_ip(ip):
    '''
    Remove an entry from the aliases file
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_aliases.rm_alias alias
    '''
    ip = _check_ip(ip)

    current_ips = list_ips()
    if ip not in current_ips:
        return True

    if _pfrest():
        remaining = ' '.join(i for i in current_ips if i != ip)
        with pfrest_module.session(__salt__, __opts__, ha_sync=False):
            pfsense_config_path.set_path(__salt__, 'system/sshguard_whitelist', remaining,
                                         apply=['filter_configure', 'system_syslogd_start'], test=__opts__.get('test', False))
        return True

    client = _get_client()
    config = client.config_get()

    new_ips = []
    for current_ip in current_ips:
        if current_ip == ip:
            continue
        new_ips.append(current_ip)

    config['system']['sshguard_whitelist'] = ' '.join(new_ips)
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating alias')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating alias')

    cmd = ['php', '/opt/helpers/sshguard_whitelist.php']

    result = __salt__['cmd.run_all'](cmd,
                                     python_shell=False)

    if result['retcode'] != 0:
        raise CommandExecutionError(result['stdout'])
    return True
