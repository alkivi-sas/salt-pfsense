# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function

from salt.exceptions import CommandExecutionError


def migrated(name):
    '''
    Migrate the DHCP backend from ISC to Kea, converting the ISC custom
    options 43 (UniFi) and 132 (Yealink VLAN) to Kea custom JSON.
    Commits the change and reconfigures the DHCP service.
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    try:
        changes = __salt__['pfsense_dhcp_kea.migration_changes']()
    except CommandExecutionError as exc:
        ret['result'] = False
        ret['comment'] = str(exc)
        return ret

    if not changes:
        ret['comment'] = 'DHCP is already on Kea'
        return ret

    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'DHCP is set to be migrated to Kea'
        ret['changes'] = changes
        return ret

    ret['changes'] = __salt__['pfsense_dhcp_kea.migrate']()
    __salt__['pfsense_dhcp_kea.apply']()
    ret['comment'] = 'DHCP migrated to Kea'
    return ret


def custom_config_present(name, data, interface=None):
    '''
    Ensure the Kea custom JSON (global or for the interface) is data.
    Use pfsense_dhcp_kea.apply with watch to commit.
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    current = __salt__['pfsense_dhcp_kea.get_custom_config'](interface)
    if current == data:
        ret['comment'] = 'Kea custom config is already OK'
        return ret

    ret['changes'][interface or 'global'] = {'old': current, 'new': data}
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Kea custom config is set to be updated'
        return ret

    __salt__['pfsense_dhcp_kea.set_custom_config'](data, interface)
    ret['comment'] = 'Kea custom config updated'
    return ret


def apply(name):
    '''
    Apply pending pfSense Kea configuration changes in one commit.
    Intended to be used with watch/watch_in requisites.
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    if __opts__['test']:
        ret['comment'] = 'Pending configuration would be applied'
        return ret

    changed = __salt__['pfsense_dhcp_kea.apply']()
    if changed:
        ret['changes']['config'] = 'applied'
        ret['comment'] = 'Pending Kea configuration applied'
    else:
        ret['comment'] = 'No pending Kea changes to apply'
    return ret
