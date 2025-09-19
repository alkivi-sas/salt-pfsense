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
import copy

# Import Salt libs
import salt.utils.files
import salt.utils.stringutils
import pfsense
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

def _ensure_pending_config_loaded():
    """
    Load pfSense config once into __context__ both as original and pending.
    Pending is mutated by setters; only apply() commits it.
    """
    try:
        ctx = __context__  # noqa: F821 - provided by Salt at runtime
    except NameError:
        # Outside Salt runtime; emulate minimal context
        globals().setdefault('_local_context', {})
        ctx = _local_context

    if 'pfsense_dhcp_static_map.original_config' in ctx and 'pfsense_dhcp_static_map.pending_config' in ctx:
        return

    client = _get_client()
    full_config = client.config_get()
    # Keep deep copies to avoid accidental cross-mutation
    ctx['pfsense_dhcp_static_map.original_config'] = copy.deepcopy(full_config)
    ctx['pfsense_dhcp_static_map.pending_config'] = copy.deepcopy(full_config)

def _get_pending_config():
    _ensure_pending_config_loaded()
    try:
        return __context__['pfsense_dhcp_static_map.pending_config']  # noqa: F821
    except NameError:
        return _local_context['pfsense_dhcp_static_map.pending_config']

def _set_pending_config(new_config):
    try:
        __context__['pfsense_dhcp_static_map.pending_config'] = new_config  # noqa: F821
    except NameError:
        _local_context['pfsense_dhcp_static_map.pending_config'] = new_config

def _clear_config_cache():
    try:
        for k in [
            'pfsense_dhcp_static_map.original_config',
            'pfsense_dhcp_static_map.pending_config',
        ]:
            __context__.pop(k, None)  # noqa: F821
    except NameError:
        if '_local_context' in globals():
            for k in [
                'pfsense_dhcp_static_map.original_config',
                'pfsense_dhcp_static_map.pending_config',
            ]:
                _local_context.pop(k, None)

def _check_interface(interface):
    config = _get_pending_config()

    if interface not in config['dhcpd']:
        raise CommandExecutionError('The interface {0} does not have DHCP'.format(interface))


def list_static_maps(interface):
    '''
    Return the static maps for the interface
    '''

    _check_interface(interface)

    config = _get_pending_config()

    ret = {}
    if 'staticmap' not in config['dhcpd'][interface]:
        return ret

    for static_map in config['dhcpd'][interface]['staticmap']:
        ret[static_map['mac']] = static_map
    return ret

def _sync_ha():
    cmd = ['/etc/rc.filter_synchronize']
    __salt__['cmd.run_all'](cmd, python_shell=False)



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
        if key in kwargs and kwargs[key] is not None:
            wanted_data[key] = kwargs[key]

    _check_interface(interface)

    _ensure_pending_config_loaded()
    config = _get_pending_config()

    new_static_maps = []
    to_add = True
    if 'staticmap' in config['dhcpd'][interface]:
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
    _set_pending_config(config)
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

    _ensure_pending_config_loaded()
    config = _get_pending_config()

    new_static_maps = []
    for current_static_map in config['dhcpd'][interface]['staticmap']:
        if current_static_map['mac'] == mac:
            continue
        new_static_maps.append(current_static_map)

    config['dhcpd'][interface]['staticmap'] = new_static_maps
    _set_pending_config(config)
    return True

def apply():
    """
    Commit pending configuration changes to pfSense via FauxAPI in one call.
    Returns True if changes were applied, False if there were no pending changes.
    """
    _ensure_pending_config_loaded()
    try:
        original = __context__['pfsense_dhcp_static_map.original_config']  # noqa: F821
        pending = __context__['pfsense_dhcp_static_map.pending_config']  # noqa: F821
    except NameError:
        original = _local_context.get('pfsense_dhcp_static_map.original_config')
        pending = _local_context.get('pfsense_dhcp_static_map.pending_config')

    if original == pending:
        # Nothing to do
        return False

    client = _get_client()
    result = client.config_set(pending)

    if 'message' not in result or result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when applying pending configuration')

    _sync_ha()
    _clear_config_cache()
    return True
