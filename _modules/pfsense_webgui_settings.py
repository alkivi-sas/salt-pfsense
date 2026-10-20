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

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)


def _pfrest():
    return pfrest_module.enabled(__salt__, 'pfsense_webgui_settings')


def _config():
    if _pfrest():
        return pfsense_local.read_config()
    return _get_client().config_get()


# WebGUISettings fields of pfrest; the other webgui keys go through config_path
MODELLED = ('protocol', 'port', 'sslcertref')


def get_setting(name):
    '''
    Return the alternatives hostnames of the webgui
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_webgui_settings.get_setting nodnsrebindcheck
    '''
    config = _config()

    if name not in config['system']['webgui']:
        return False
    else:
        return config['system']['webgui'][name]


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

    current_value = get_setting(name)
    if current_value == value:
        return True

    if _pfrest():
        test = __opts__.get('test', False)
        with pfrest_module.session(__salt__, __opts__, ha_sync=False) as api:
            if name in MODELLED:
                # always applied by pfrest: the WebGUI (and the API) restart
                api.patch('system/webgui/settings', {name: int(value) if name == 'port' else value})
            elif name in ['nodnsrebindcheck', 'nohttpreferercheck'] and not value:
                pfsense_config_path.delete_path(__salt__, 'system/webgui/' + name, test=test)
            else:
                flag = name in ['nodnsrebindcheck', 'nohttpreferercheck']
                pfsense_config_path.set_path(__salt__, 'system/webgui/' + name, '' if flag else value, test=test)
        return True


    client = _get_client()
    config = client.config_get()

    if name in ['nodnsrebindcheck', 'nohttpreferercheck']:
        if value:
            config['system']['webgui'][name] = ''
        elif name in config['system']['webgui']:
            del config['system']['webgui'][name]
    else:
        config['system']['webgui'][name] = value

    result = client.config_set(config)

    if 'message' not in result:
        raise CommandExecutionError('Problem when setting {0} to {1}'.format(name, value))
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when setting {0} to {1}'.format(name, value))
    return True
