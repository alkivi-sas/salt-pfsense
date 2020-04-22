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
import sys

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

PY3 = sys.version_info[0] >= 3

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


def get_config():
    '''
    Return if the final level of the name exist in the XML.
    exemple zabbixagentlts.config.userparams
    Check that zabbixagentlts.config exist

    Return True or False
    '''
    client = _get_client()
    config = client.config_get()

    if 'installedpackages' not in config:
        raise CommandExecutionError('config is not valid : key {0} not found'.format('installedpackages'))
    config = config['installedpackages']

    if 'zabbixagentlts' not in config:
        raise CommandExecutionError('config is not valid : key {0} not found'.format('zabbixagentlts'))

    config = config['zabbixagentlts']

    if 'config' not in config:
        raise CommandExecutionError('config is not valid : key {0} not found'.format('config'))

    config = config['config']
    if not isinstance(config, list):
        raise CommandExecutionError('Dont know what to do')
    if len(config) != 1:
        raise CommandExecutionError('Dont know what to do')
    config = config[0]

    return config


def _decode_value(value, source):
    '''
    Format according to name.
    '''
    res = value
    if source == 'userparams':
        res = base64.b64decode(value)
        if PY3:
            res = res.decode('utf-8')
    return res


def _encode_value(value, source):
    '''
    Format according to name.
    '''
    res = value
    if source == 'userparams':
        if PY3:
            value = value.encode('utf-8')
        res = base64.b64encode(value)
        if PY3:
            res = res.decode('utf-8')
    return res


def get_value(name):
    '''
    Return the value of a key.
    '''
    config = get_config()
    if name not in config:
        raise CommandExecutionError('Key {0} not in config'.format(name))
    
    return _decode_value(config[name], name)


def set_value(name, value):
    '''
    Return the target associated with an static_map
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_zabbix_configuration.set_value userparams 'UserParameter=users,who | wc -l'
    '''

    client = _get_client()
    config = client.config_get()
    zabbix_config = get_config()
    wanted_value = _encode_value(value, name)
    zabbix_config[name] = wanted_value

    config['installedpackages']['zabbixagentlts']['config'] = [zabbix_config]
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating static_map')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating static_map')
    return True
