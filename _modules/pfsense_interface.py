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

KEYS = {
    'if': {
        'mandatory': True,
        'default': None,
        'type': 'string',
    },
    'ipaddr': {
        'mandatory': True,
        'default': None,
        'type': 'string',
    },
    'subnet': {
        'mandatory': True,
        'default': None,
        'type': 'integer',
    },
    'descr': {
        'mandatory': True,
        'default': None,
        'type': 'string',
    },
    'enable': { 
        'mandatory': False,
        'default': True,
        'type': 'boolean',
    },
    'spoofmac': {
        'mandatory': False,
        'default': '',
        'type': 'string',
    },
    'ipaddrv6': {
        'mandatory': False,
        'default': None,
        'type': 'string',
    },
    'subnetv6': {
        'mandatory': False,
        'default': None,
        'type': 'string',
    },
    'gateway': {
        'mandatory': False,
        'default': None,
        'type': 'string',
    },
    'blockbogons': { 
        'mandatory': True,
        'default': True,
        'type': 'boolean',
    },
    'blockpriv': {
        'mandatory': True,
        'default': None,
        'type': 'boolean',
    },
}

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)


def list_interfaces():
    '''
    Return the interfaces found in the interfaces file in this format::
        {'interface': {'data' ....}
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_interface.list_interfaces
    '''
    client = _get_client()
    config = client.config_get()

    ret = {}
    for interface, data in config['interfaces'].items():
        ret[interface] = {}
        for key, key_data in KEYS.items():
            key_type = key_data['type']

            if key_type == 'boolean':
                if key in data:
                    ret[interface][key] = True
                else:
                    ret[interface][key] = False
            else:
                if key in data:
                    ret[interface][key] = data[key]


    return ret


def list_wan_interfaces():
    '''
    Return the list of wan interfaces.
    Wan interfaces are interface with gateway or pppoe
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_interface.list_interfaces
    '''
    interfaces = list_interfaces()
    wan_interfaces = {}
    for interface, data in interfaces.items():
        if 'gateway' in data and data['gateway']:
            wan_interfaces[interface] = data
        elif 'ipaddr' in data and data['ipaddr'] == 'pppoe':
            wan_interfaces[interface] = data
    return wan_interfaces


def get_interface(interface):
    '''
    Return the data associated to an interface
    Return None if not found
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_interfaces.get_interface opt3
    '''
    interfaces = list_interfaces()
    if interface in interfaces:
        return interfaces[interface]
    return None


def has_interface(interface):
    '''
    Check if an interface exists
    Return True / False
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_interface.has_interface opt3
    '''
    result = get_interface(interface)
    if result is None:
        return False
    else:
        return True


def need_changes(interface):
    '''
    Return a list of key that need updates
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_interface.need_changes opt3 '{blockbogons:False}'
    '''
    keys_to_update = []
    current_data = get_interface(interface)
    if not current_data:
        raise CommandExecutionError('Unable to get interface {0}'.format(interface))

    for key, key_data in KEYS.items():
        key_type = key_data['type']

        if key in wanted_data:
            if key_type == 'boolean':
                wanted_value = wanted_data[key]
                # If we want True and is actually False
                if wanted_data and key not in current_data:
                    logger.debug('key {0} differs, '.format(key) +
                                 'actual {0} vs'.format(False) +
                                 'wanted {0}'.format(True))
                    keys_to_update.add(key)
                # If we want False and is actually True
                elif not wanted_data and key in current_data:
                    logger.debug('key {0} differs, '.format(key) +
                                 'actual {0} vs'.format(True) +
                                 'wanted {0}'.format(False))
                    keys_to_update.add(key)
            else:
                if wanted_data[key] != current_data[key]:
                    logger.debug('key {0} differs, '.format(key) +
                                 'actual {0} vs'.format(current_data[key]) +
                                 'wanted {0}'.format(wanted_data[key]))
                    keys_to_update.add(key)
    return keys_to_update


def set_interface(interface, 
                  ifname,
                  ipaddr,
                  subnet,
                  descr,
                  **kwargs):
    '''
    Set an interface
    exist.
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_interface.set_interface
    '''

    wanted_data = {
        'if': ifname,
        'ipaddr': ipaddr,
        'subnet': str(subnet),
        'descr': descr,
    }

    # check kwargs and install default if needed
    for key, key_data in KEYS.items():
        key_type = key_data['type']
        key_default = key_data['default']

        if key in kwargs and kwargs[key] is not None:
            if key_type == 'boolean':
                wanted_data[key] = ''
            else:
                wanted_data[key] = str(kwargs[key])
        elif key_default is not None:
            if key_type == 'boolean' and key_default:
                wanted_data[key] = ''
            else:
                wanted_data[key] = key_default

    client = _get_client()
    config = client.config_get()

    new_interfaces = {}
    to_add = True

    for ifname, ifdata in config['interfaces'].items():
        if ifname == interface:
            to_add = False

            # Parse all key
            for key, key_data in KEYS.items():
                key_type = key_data['type']

                if key_type == 'boolean':
                    if key in ifdata and key not in wanted_data:
                        logger.debug('Deleting boolean key {0}'.format(key))
                        del ifdata[key]
                    elif key not in ifdata and key in wanted_data:
                        logger.debug('Setting boolean key {0}'.format(key))
                        ifdata[key] = ''
                    else:
                        logger.debug('No changes for boolean key {0}'.format(key))
                elif key in wanted_data:
                    value = str(wanted_data[key])
                    if key not in ifdata:
                        logger.debug('Setting key {0} to {1}'.format(key, value))
                        ifdata[key] = value
                    elif ifdata[key] != value:
                        logger.debug('Updating {0} to {1}'.format(key, value))
                        ifdata[key] = value
                    else:
                        logger.debug('No changes for key {0}'.format(key))
                else:
                    logger.debug('Key {0} not in asked changes'.format(key))

        new_interfaces[ifname] = ifdata

    if to_add:
        logger.debug('adding with data {0}'.format(wanted_data))
        new_interfaces[interface] = wanted_data

    config['interfaces'] = new_interfaces
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating interface')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating interface')

    # Now reload interface
    client.send_event('interface reconfigure {0}'.format(interface))
    return True


def rm_interface(interface):
    '''
    Remove an entry from the interfaces file
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_interfaces.rm_interface interface
    '''
    if not get_interface(interface):
        return True

    client = _get_client()
    config = client.config_get()

    new_interfaces = {}
    for ifname, ifdata in config['interfaces'].items():
        if ifname == interface:
            continue
        new_interfaces[ifname] = ifdata

    config['interfaces'] = new_interfaces
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating interface')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating interface')

    # Now reload
    client.function_call({
        'function': 'interface_bring_down',
        'args': [interface],
        'includes': ['interfaces.inc'],
    })
    return True
