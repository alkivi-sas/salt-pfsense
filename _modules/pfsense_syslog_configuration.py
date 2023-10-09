# -*- coding: utf-8 -*-
"""
Module for running pfsense module via fauxapi
"""
from __future__ import absolute_import

# Import Python libs
import os
import atexit
import logging

# Import Salt libs
import pfsense
from salt.exceptions import (
    CommandExecutionError,
    SaltInvocationError,
)

HAS_CHANGES = False
BOOLEAN_NAMES = [
    'reverse',
    'nologdefaultblock',
    'nologdefaultpass',
    'nologbogons',
    'nologprivatenets',
    'nolognginx',
    'rawfilter',
    'disablelocallogging',
    'enable',
    'logall'
]

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False


def _get_client():
    return pfsense.FauxapiLib.get_singleton(debug=True)


def exit_handler():
    global HAS_CHANGES
    if HAS_CHANGES:
        client = _get_client()
        params = {'function': 'system_syslogd_start'}
        client.function_call(params)

        params = {'function': 'filter_pflog_start', 'args': 'true'}
        client.function_call(params)


def get_setting(name):
    '''
    Return the alternatives hostnames of the webgui
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_webgui_settings.get_setting nodnsrebindcheck
    '''
    client = _get_client()
    config = client.config_get()

    if name not in config['syslog']:
        return False
    elif name in BOOLEAN_NAMES:
        if name in config['syslog']:
            return True
        else:
            return False
    else:
        return config['syslog'][name]


def set_setting(name, value):
    '''
    Add the entry to the list
    exist.
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_aliases.set_setting nodnsrebindcheck True
    '''

    if name == '':
        raise SaltInvocationError('name can not be an empty string')
    if value is None:
        raise SaltInvocationError('value can not be None')



    client = _get_client()
    config = client.config_get()

    current_value = get_setting(name)
    if current_value == value:
        return True

    if name in BOOLEAN_NAMES:
        if value:
            config['syslog'][name] = ''
        elif name in config['syslog']:
            del config['syslog'][name]
    else:
        config['syslog'][name] = value

    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when setting {0} to {1}'.format(name, value))
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when setting {0} to {1}'.format(name, value))

    # reload syslog
    global HAS_CHANGES
    HAS_CHANGES = True

    return True

atexit.register(exit_handler)
