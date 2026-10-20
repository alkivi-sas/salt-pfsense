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
import pfrest_cron
import pfrest_module
import pfsense_local
from salt.exceptions import (
    CommandExecutionError,
    SaltInvocationError,
)

PY3 = sys.version_info[0] >= 3

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)

def _pfrest():
    return pfrest_module.enabled(__salt__, 'pfsense_cron')


def _config():
    # The custom identifier field only lives in config.xml: reads stay local on pfrest
    if _pfrest():
        return pfsense_local.read_config()
    return _get_client().config_get()


def _generate_identifier(cron):
    if 'identifier' in cron:
        return cron['identifier']

    string_array = []
    for key in ['command', 'mday', 'hour', 'who', 'month', 'minute', 'wday']:
        string_array.append(str(cron[key]))
    string_to_hash = ''.join(string_array)
    if PY3:
        string_to_hash = string_to_hash.encode('utf-8')
    return hashlib.sha256(string_to_hash).hexdigest()


def list_cron():
    config = _config()

    response_data = {}
    for cron in config['cron']['item']:
        identifier = _generate_identifier(cron)
        response_data[identifier] = cron
    return response_data


def get_cron(identifier, command=None):
    """Identifier can be an hexdigest, identifier or command."""
    cron_index, cron = _get_cron(identifier, command)
    return cron


def add_cron(identifier, command, who='root', mday='*', hour='*', month='*', wday='*', minute='*'):

    mday = str(mday)
    hour = str(hour)
    month = str(month)
    wday = str(wday)
    minute = str(minute)

    new_cron = {
            'mday': mday,
            'hour': hour,
            'month': month,
            'wday': wday,
            'minute': minute,
            'command': command,
            'identifier': identifier,
            'who': who,
    }

    cron_index, cron = _get_cron(identifier, command)
    if cron_index is not None:
        raise CommandExecutionError('cron {0} already exists'.format(identifier))

    if _pfrest():
        with pfrest_module.session(__salt__, __opts__, ha_sync=False) as api:
            pfrest_cron.add_cron(api, new_cron)
        return new_cron

    client = _get_client()
    config = client.config_get()

    patch_system_cron = {
        'cron': {
            'item': config['cron']['item']
        }
    }
    patch_system_cron['cron']['item'].append(new_cron)

    response = client.config_patch(patch_system_cron)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add cron', response['message'])

    return new_cron

def manage_cron(identifier, command=None, who=None, mday=None, hour=None, month=None, wday=None, minute=None):

    cron_index, cron = _get_cron(identifier, command)
    if cron_index is None:
        raise CommandExecutionError('cron {0} does not exist'.format(identifier))
    current_command = cron['command']

    if command is not None:
        cron['command'] = command
    if who is not None:
        cron['who'] = who 
    if mday is not None:
        cron['mday'] = mday 
    if hour is not None:
        cron['hour'] = hour 
    if month is not None:
        cron['month'] = month 
    if wday is not None:
        cron['wday'] = wday 
    if minute is not None:
        cron['minute'] = minute 
    if 'identifier' not in cron:
        cron['identifier'] = identifier
    elif cron['identifier'] != identifier:
        cron['identifier'] = identifier

    if _pfrest():
        with pfrest_module.session(__salt__, __opts__, ha_sync=False) as api:
            pfrest_cron.manage_cron(api, current_command, cron)
        return cron

    client = _get_client()
    config = client.config_get()

    patch_system_cron = {
        'cron': {
            'item': config['cron']['item']
        }
    }
    patch_system_cron['cron']['item'][cron_index] = cron

    response = client.config_patch(patch_system_cron)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to manage cron', response['message'])

    return cron


def remove_cron(identifier, command=None):

    cron_index, cron = _get_cron(identifier, command)
    if cron_index is None:
        return True

    if _pfrest():
        with pfrest_module.session(__salt__, __opts__, ha_sync=False) as api:
            pfrest_cron.remove_cron(api, cron['command'])
        return True

    client = _get_client()
    config = client.config_get()
    patch_system_cron = {
        'cron': {
            'item': config['cron']['item']
        }
    }
    del(patch_system_cron['cron']['item'][cron_index])

    response = client.config_patch(patch_system_cron)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to remove cron', response['message'])


    return True


# internal helper functions
# =========================================================================

def _get_cron(identifier, command):
    config = _config()

    cron = None
    correct_index = 0
    cron_index = 0

    for cron_data in config['cron']['item']:
        cron_identifier = _generate_identifier(cron_data)

        if identifier == cron_identifier:
            if cron is None:
                cron = cron_data
                correct_index = cron_index
                continue
            else:
                raise CommandExecutionError('Multiple cron found')

        if cron_data['command'] == command:
            if cron is None:
                cron = cron_data
                correct_index = cron_index
            else:
                raise CommandExecutionError('Multiple cron found')
        cron_index += 1

    if cron is None:
        return None, None

    # pfrest does not store the custom identifier: a job found by command carries the asked one
    if _pfrest() and 'identifier' not in cron and identifier is not None:
        cron = dict(cron, identifier=identifier)

    return correct_index, cron
