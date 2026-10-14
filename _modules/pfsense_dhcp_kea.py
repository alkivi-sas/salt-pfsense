# -*- coding: utf-8 -*-
"""
Module to migrate pfSense DHCP from ISC to Kea via fauxapi

ISC custom options (dhcpd:<if>:numberoptions) are converted to Kea custom JSON:
- kea:custom_kea_config holds the global option-def
- dhcpd:<if>:custom_kea_config holds the option-data of the interface
Both are base64 encoded JSON, as written by the webGUI.
"""
from __future__ import absolute_import

# Import Python libs
import os
import json
import base64
import logging
import copy

# Import Salt libs
import pfsense
from salt.exceptions import (
    CommandExecutionError,
    SaltInvocationError,
)

logger = logging.getLogger(__name__)

CONTEXT_ORIGINAL = 'pfsense_dhcp_kea.original_config'
CONTEXT_PENDING = 'pfsense_dhcp_kea.pending_config'

UNIFI_OPTION = 'unificontroller'
YEALINK_OPTION = 'yealink-vlan'

OPTION_DEF = {
    'option-def': [
        {'code': 43, 'name': UNIFI_OPTION, 'space': 'dhcp4', 'type': 'binary'},
        {'code': 132, 'name': YEALINK_OPTION, 'space': 'dhcp4', 'type': 'string'},
    ]
}


def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False


def _get_client():
    return pfsense.FauxapiLib(debug=True)


def _get_context():
    try:
        return __context__  # noqa: F821 - provided by Salt at runtime
    except NameError:
        return globals().setdefault('_local_context', {})


def _get_pending_config():
    """
    Load pfSense config once into __context__ both as original and pending.
    Pending is mutated by setters; only apply() commits it.
    """
    ctx = _get_context()
    if CONTEXT_PENDING not in ctx:
        full_config = _get_client().config_get()
        ctx[CONTEXT_ORIGINAL] = copy.deepcopy(full_config)
        ctx[CONTEXT_PENDING] = copy.deepcopy(full_config)
    return ctx[CONTEXT_PENDING]


def _clear_config_cache():
    ctx = _get_context()
    ctx.pop(CONTEXT_ORIGINAL, None)
    ctx.pop(CONTEXT_PENDING, None)


def _sync_ha():
    cmd = ['/etc/rc.filter_synchronize']
    __salt__['cmd.run_all'](cmd, python_shell=False)


def _decode(raw):
    if not raw:
        return None
    return json.loads(base64.b64decode(raw).decode('utf-8'))


def _encode(data):
    return base64.b64encode(json.dumps(data, indent=2).encode('utf-8')).decode('utf-8')


def _dhcpd(config):
    dhcpd = config.get('dhcpd')
    return dhcpd if isinstance(dhcpd, dict) else {}


def _dhcp_interfaces(config):
    return [name for name, data in _dhcpd(config).items() if isinstance(data, dict) and 'enable' in data]


def _number_options(config, interface):
    numberoptions = config['dhcpd'][interface].get('numberoptions')
    if not isinstance(numberoptions, dict):
        return []
    items = numberoptions.get('item') or []
    if isinstance(items, dict):
        items = [items]
    return items


def get_backend():
    '''
    Return the DHCP backend, isc or kea
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_dhcp_kea.get_backend
    '''
    return _get_pending_config().get('dhcpbackend') or 'isc'


def set_backend(backend):
    '''
    Set the DHCP backend in the pending config
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_dhcp_kea.set_backend kea
    '''
    if backend not in ['isc', 'kea']:
        raise SaltInvocationError('backend must be isc or kea')
    _get_pending_config()['dhcpbackend'] = backend
    return True


def get_custom_config(interface=None):
    '''
    Return the decoded Kea custom JSON, global or for the interface
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_dhcp_kea.get_custom_config
        salt '*' pfsense_dhcp_kea.get_custom_config lan
    '''
    config = _get_pending_config()
    if interface is None:
        kea = config.get('kea')
        return _decode(kea.get('custom_kea_config') if isinstance(kea, dict) else None)

    if interface not in _dhcpd(config):
        raise CommandExecutionError('The interface {0} does not have DHCP'.format(interface))
    return _decode(config['dhcpd'][interface].get('custom_kea_config'))


def set_custom_config(data, interface=None):
    '''
    Set the Kea custom JSON, global or for the interface, in the pending config
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_dhcp_kea.set_custom_config '{"option-def": []}'
    '''
    if not isinstance(data, dict):
        data = json.loads(data)

    config = _get_pending_config()
    if interface is None:
        if not isinstance(config.get('kea'), dict):
            config['kea'] = {}
        config['kea']['custom_kea_config'] = _encode(data)
        return True

    if interface not in _dhcpd(config):
        raise CommandExecutionError('The interface {0} does not have DHCP'.format(interface))
    config['dhcpd'][interface]['custom_kea_config'] = _encode(data)
    return True


def numberoptions_to_kea(interface):
    '''
    Convert the ISC custom options of the interface to Kea option-data.
    Only options 43 (UniFi controller) and 132 (Yealink VLAN) are handled,
    any other option raises an error.
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_dhcp_kea.numberoptions_to_kea lan
    '''
    config = _get_pending_config()
    option_data = []
    for item in _number_options(config, interface):
        value = base64.b64decode(item.get('value', '')).decode('utf-8')
        if item.get('number') == '43':
            data = value.replace(':', '').upper()
            try:
                bytes.fromhex(data)
            except ValueError:
                raise CommandExecutionError(
                    'Option 43 on {0} is not hex: {1}'.format(interface, value))
            option_data.append({'name': UNIFI_OPTION, 'data': data})
        elif item.get('number') == '132':
            option_data.append({'name': YEALINK_OPTION, 'data': value, 'always-send': True})
        else:
            raise CommandExecutionError(
                'Option {0} on {1} is not handled by the Kea migration'.format(item.get('number'), interface))

    if not option_data:
        return None
    return {'option-data': option_data}


def migration_changes():
    '''
    Return what migrate() would change, without touching the config.
    Raise an error when the firewall can not be migrated safely.
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_dhcp_kea.migration_changes
    '''
    config = _get_pending_config()
    changes = {}

    for interface in _dhcp_interfaces(config):
        if config['dhcpd'][interface].get('failover_peerip'):
            raise CommandExecutionError(
                'DHCP failover is set on {0}, Kea HA must be migrated by hand'.format(interface))

    interfaces_data = {}
    for interface in _dhcp_interfaces(config):
        wanted = numberoptions_to_kea(interface)
        if wanted is None:
            continue
        current = get_custom_config(interface)
        if current is not None and current != wanted:
            raise CommandExecutionError(
                'Interface {0} already has a different Kea custom config: {1}'.format(interface, current))
        interfaces_data[interface] = wanted
        changes[interface] = {'old': current, 'new': wanted, 'numberoptions': 'removed'}

    if interfaces_data:
        current = get_custom_config()
        if current != OPTION_DEF:
            if current is not None:
                raise CommandExecutionError('Kea already has a different global custom config: {0}'.format(current))
            changes['global'] = {'old': current, 'new': OPTION_DEF}

    if get_backend() != 'kea':
        changes['dhcpbackend'] = {'old': get_backend(), 'new': 'kea'}

    return changes


def migrate():
    '''
    Migrate the pending config to Kea: global option-def, option-data per
    interface, ISC numberoptions removed and backend set to kea.
    Call apply() to commit.
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_dhcp_kea.migrate
    '''
    changes = migration_changes()
    config = _get_pending_config()

    for interface, change in changes.items():
        if interface == 'global':
            set_custom_config(change['new'])
        elif interface != 'dhcpbackend':
            set_custom_config(change['new'], interface)
            config['dhcpd'][interface]['numberoptions'] = ''

    if 'dhcpbackend' in changes:
        set_backend('kea')
    return changes


def apply():
    """
    Commit pending configuration changes to pfSense via FauxAPI in one call,
    then reconfigure the DHCP service.
    Returns True if changes were applied, False if there were no pending changes.
    """
    _get_pending_config()
    ctx = _get_context()
    if ctx[CONTEXT_ORIGINAL] == ctx[CONTEXT_PENDING]:
        return False

    client = _get_client()
    result = client.config_set(ctx[CONTEXT_PENDING])

    if 'message' not in result or result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when applying pending configuration')

    client.function_call({
        'function': 'services_dhcpd_configure',
        'includes': ['services.inc'],
    })
    _sync_ha()
    _clear_config_cache()
    return True
