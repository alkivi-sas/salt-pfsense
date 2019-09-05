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

    available_keys = ['descr', 'ipaddr', 'spoofmac', 'if', 'subnet', 'ipaddrv6', 'subnetv6', 'gateway']
    boolean_keys = ['enable', 'blockbogons', 'blockpriv']

    ret = {}
    for interface, data in config['interfaces'].items():
        ret[interface] = {}
        for key in available_keys:
            if key in data and data[key]:
                ret[interface][key] = data[key]
        for key in boolean_keys:
            if key in data:
                ret[interface][key] = True
            else:
                ret[interface][key] = False

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
        if 'gateway' in data:
            wan_interfaces[interface] = data
        elif 'ipaddr' in data and data['ipaddr'] == 'pppoe':
            wan_interfaces[interface] = data
    return wan_interfaces


def get_interface(interface):
    '''
    Return the target associated with an interface
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_interfaces.get_target interface
    '''
    interfaces = list_interfaces()
    if interface not in interfaces:
        raise CommandExecutionError('Unknow interface')
    return interfaces[interface]
