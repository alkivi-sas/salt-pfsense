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

# Import 3rd-party libs
from salt.ext import six
from salt.ext.six.moves import range

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)

def _check_interface(interface):
    client = _get_client()
    config = client.config_get()

    if interface not in config['dhcpd']:
        raise CommandExecutionError('The interface {0} does not have DHCP'.format(interface))


def list_static_maps(interface):
    '''
    Return the static maps for the interface
    '''

    _check_interface(interface)

    client = _get_client()
    config = client.config_get()

    ret = {}
    for static_map in config['dhcpd'][interface]['staticmap']:
        ret[static_map['mac']] = static_map
    return ret


def get_static_map(interface, mac):
    '''
    Return the target associated with an static_map
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_static_maps.get_target static_map
    '''
    static_maps = list_static_maps(interface)
    if mac in static_maps:
        return static_maps[mac]
    return None


def has_static_map(interface, mac):
    '''
    Return true if the static_map/target is set
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_static_maps.has_target static_map target
    '''
    static_maps = list_static_maps(interface)
    if mac not in static_maps:
        return False
    else:
        return True


def set_static_map(interface, mac, ipaddr, hostname, **kwargs):
    '''
    Set the entry in the static_maps file for the given static_map, this will overwrite
    any previous entry for the given static_map or create a new one if it does not
    exist.
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_static_maps.set_target static_map target
    '''

    keys_to_check = [
        'cid',
        'descr',
        'filename',
        'rootpath',
        'defaultleasetime',
        'maxleasetime',
        'gateway',
        'domain',
        'domainsearchlist',
        'ddnsdomain',
        'ddnsdomainprimary',
        'ddnsdomainkeyname',
        'ddnsdomainkey',
        'tftp',
        'ldap',
    ]

    wanted_data = {
        'mac': mac,
        'ipaddr': ipaddr,
        'hostname': hostname
    }

    for key in keys_to_check:
        if key in kwargs:
            wanted_data[key] = kwargs[key]

    _check_interface(interface)

    client = _get_client()
    config = client.config_get()

    new_static_maps = []
    to_add = True
    for current_static_map in config['dhcpd'][interface]['staticmap']:
        if current_static_map['mac'] == mac:
            to_add = False
            for key, value in wanted_data.items():
                if key not in current_static_map:
                    logger.debug('setting {0} to {1}'.format(key, value))
                    current_static_map[key] = value
                elif current_static_map[key] != wanted_data[key]:
                    logger.debug('updating {0} to {1}'.format(key, value))
                    to_update = True
                    current_static_map[key] = value
                else:
                    continue
        new_static_maps.append(current_static_map)

    if to_add:
        logger.debug('adding with data {0}'.format(wanted_data))
        new_static_maps.append(wanted_data)

    config['dhcpd'][interface]['staticmap'] = new_static_maps
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating static_map')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating static_map')
    return True


def rm_static_map(interface, mac):
    '''
    Remove an entry from the static_maps file
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_static_maps.rm_static_map static_map
    '''
    if not get_static_map(interface, mac):
        return True

    client = _get_client()
    config = client.config_get()

    new_static_maps = []
    for current_static_map in config['dhcpd'][interface]['staticmap']:
        if current_static_map['mac'] == mac:
            continue
        new_static_maps.append(current_static_map)

    config['dhcpd'][interface]['staticmap'] = new_static_maps
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating static_map')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating static_map')
    return True
