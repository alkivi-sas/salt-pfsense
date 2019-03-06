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


def list_aliases():
    '''
    Return the aliases found in the aliases file in this format::
        {'alias': 'target'}
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_aliases.list_aliases
    '''
    client = _get_client()
    config = client.config_get()

    ret = {}
    for alias in config['aliases']['alias']:
        addresses = alias['address'].split(' ')
        alias['addresses'] = addresses
        ret[alias['name']] = alias
    return ret


def get_target(alias):
    '''
    Return the target associated with an alias
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_aliases.get_target alias
    '''
    aliases = list_aliases()
    if alias in aliases:
        return aliases[alias]['addresses']
    return []


def has_target(alias, target):
    '''
    Return true if the alias/target is set
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_aliases.has_target alias target
    '''
    if alias == '':
        raise SaltInvocationError('alias can not be an empty string')

    if target == '':
        raise SaltInvocationError('target can not be an empty string')

    aliases = list_aliases()
    if alias not in aliases:
        return False

    global_presence = True
    if isinstance(target, list):
        for t in target:
            if t not in aliases[alias]['addresses']:
                global_presence = False
                break
    else:
        if target not in aliases[alias]['addresses']:
            global_presence = False
            
    return global_presence


def set_target(alias, target, type=None, descr=None, detail=None):
    '''
    Set the entry in the aliases file for the given alias, this will overwrite
    any previous entry for the given alias or create a new one if it does not
    exist.
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_aliases.set_target alias target
    '''

    if alias == '':
        raise SaltInvocationError('alias can not be an empty string')

    if target == '':
        raise SaltInvocationError('target can not be an empty string')

    targets = []
    if isinstance(target, list):
        targets = target
    else:
        targets = [target]

    is_already_ok = True
    current_targets = get_target(alias)
    for target in targets:
        if target not in current_targets:
            is_already_ok = False
            break
    if is_already_ok:
        return True

    client = _get_client()
    config = client.config_get()

    new_aliases = []
    to_add = True
    for current_alias in config['aliases']['alias']:
        if current_alias['name'] == alias:
            to_add = False
            current_alias['address'] = ' '.join(targets)
            if descr:
                current_alias['descr'] = descr
            if detail:
                current_alias['detail'] = detail
            if type and type != current_alias['type']:
                raise CommandExecutionError('You ask for type {0} but already present as {1}'.format(type, current_alias['type']))
        new_aliases.append(current_alias)

    if to_add:
        if type not in ['port', 'network', 'host']:
            raise SaltInvocationError('type is not correct')
        new_alias = {
                'name': alias,
                'address': ' '.join(targets),
                'type': type
        }
        if descr:
            new_alias['descr'] = descr
        if detail:
            new_alias['detail'] = detail
        new_aliases.append(new_alias)

    config['aliases']['alias'] = new_aliases
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating alias')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating alias')
    return True


def rm_alias(alias):
    '''
    Remove an entry from the aliases file
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_aliases.rm_alias alias
    '''
    if not get_target(alias):
        return True

    client = _get_client()
    config = client.config_get()

    new_aliases = []
    for current_alias in config['aliases']['alias']:
        if current_alias['name'] == alias:
            continue
        new_aliases.append(current_alias)

    config['aliases']['alias'] = new_aliases
    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when updating alias')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating alias')
    return True
