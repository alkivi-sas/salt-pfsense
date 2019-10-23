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


def list_vlans():
    '''
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_vlan.list_vlan
    '''
    client = _get_client()
    config = client.config_get()

    ret = {}
    if 'vlan' not in config['vlans']:
        return ret

    for vlan in config['vlans']['vlan']:
        vlanif = vlan['vlanif']
        ret[vlanif] = vlan
    return ret


def get_vlan(interface, tag):
    '''
    Return the target associated with an vlan
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_vlan.get_target vlan
    '''
    vlans = list_vlans()
    vlanif = '{0}.{1}'.format(interface, tag)
    if vlanif in vlans:
        return vlans[vlanif]
    return None


def has_vlan(interface, tag):
    '''
    Return true if the vlan/target is set
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_vlan.has_target vlan target
    '''
    result = get_vlan(interface, tag)
    if not result:
        return False
    else:
        return True

def set_vlan(interface, tag, descr=None, pcp=None):
    '''
    Set the entry in the vlan file for the given vlan, this will overwrite
    any previous entry for the given vlan or create a new one if it does not
    exist.
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_vlan.set_target vlan target
    '''
    vlanif = '{0}.{1}'.format(interface, tag)

    if pcp is None:
        pcp = ''
    if descr is None:
        descr = ''

    wanted_data = {
        'vlanif': vlanif,
        'if': interface,
        'tag': str(tag),
        'descr': descr,
        'pcp': str(pcp),
    }

    client = _get_client()
    config = client.config_get()

    new_vlan = []
    to_add = True
    for current_vlan in config['vlans']['vlan']:
        if current_vlan['vlanif'] == vlanif:
            to_add = False
            for key, value in wanted_data.items():
                if key not in current_vlan:
                    logger.debug('setting {0} to {1}'.format(key, value))
                    current_vlan[key] = value
                elif current_vlan[key] != value:
                    logger.debug('updating {0} from {1} to {2}'.format(key, current_vlan[key], value))
                    to_update = True
                    current_vlan[key] = value
                else:
                    continue
        new_vlan.append(current_vlan)

    if to_add:
        logger.debug('adding with data {0}'.format(wanted_data))
        new_vlan.append(wanted_data)

    config['vlans']['vlan'] = new_vlan
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating vlan')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating vlan')
    return True


def rm_vlan(interface, tag):
    '''
    Remove an entry from the vlan file
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_vlan.rm_vlan vlan
    '''
    if not get_vlan(interface, tag):
        return True

    client = _get_client()
    config = client.config_get()

    vlanif = '{0}.{1}'.format(interface, tag)

    new_vlan = []
    for current_vlan in config['vlans']['vlan']:
        if current_vlan['vlanif'] == vlanif:
            continue
        new_vlan.append(current_vlan)

    config['vlans']['vlan'] = new_vlan
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating vlan')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating vlan')
    return True
