# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys


KEYS = {
    'if': {
        'mandatory': True,
        'default': None,
        'type': 'string',
    },
    'ipaddr': {
        'mandatory': True,
        'default': None,
        'type': 'string',
    },
    'subnet': {
        'mandatory': True,
        'default': None,
        'type': 'integer',
    },
    'descr': {
        'mandatory': True,
        'default': None,
        'type': 'string',
    },
    'enable': { 
        'mandatory': False,
        'default': True,
        'type': 'boolean',
    },
    'spoofmac': {
        'mandatory': False,
        'default': '',
        'type': 'string',
    },
    'ipaddrv6': {
        'mandatory': False,
        'default': None,
        'type': 'string',
    },
    'subnetv6': {
        'mandatory': False,
        'default': None,
        'type': 'string',
    },
    'gateway': {
        'mandatory': False,
        'default': None,
        'type': 'string',
    },
    'blockbogons': { 
        'mandatory': True,
        'default': True,
        'type': 'boolean',
    },
    'blockpriv': {
        'mandatory': True,
        'default': None,
        'type': 'boolean',
    },
}


def present(name,
            ifname,
            ipaddr,
            subnet,
            descr,
            **kwargs):
    '''
    '''

    interface = name
    ret = {'name': interface,
           'changes': {},
           'result': True,
           'comment': ''}

    wanted_data = {
        'if': ifname,
        'ipaddr': ipaddr,
        'subnet': str(subnet),
        'descr': descr,
    }

    # check kwargs and install default if needed
    for key, key_data in KEYS.items():
        key_type = key_data['type']
        key_default = key_data['default']

        if key in kwargs and kwargs[key] is not None:
            if key_type == 'boolean':
                wanted_data[key] = ''
            else:
                wanted_data[key] = str(kwargs[key])
        elif key_default is not None:
            if key_type == 'boolean' and key_default:
                wanted_data[key] = ''
            else:
                wanted_data[key] = key_default

    is_present = __salt__['pfsense_interface.has_interface'](interface)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Interface {0} is set to be created'.format(interface)
            return ret
        need_changes = __salt__['pfsense_interface.need_changes'](interface, wanted_data)
        if not need_changes:
            ret['comment'] = 'Interface is already OK'
        else:
            ret['comment'] = 'Interface is set to be updated'
        return ret

    data = __salt__['pfsense_interface.set_interface'](
            interface,
            ifname=ifname,
            ipaddr=ipaddr,
            subnet=subnet,
            descr=descr,
            **kwargs)

    if is_present: 
        ret['changes'][interface] = 'Updated'
        ret['comment'] = ('Interface {0} updated'.format(interface))
    else:
        ret['changes'][interface] = 'New'
        ret['comment'] = ('Interface {0} added'.format(interface))
    return ret


def absent(name):
    interface = name

    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_interface.has_interface'](name)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Interface {0} is not present'.format(interface)
        else:
            ret['comment'] = 'Interface {0} set to be removed'.format(interface)
        return ret

    data = __salt__['pfsense_interface.rm_interface'](interface)

    if is_present: 
        ret['changes'][interface] = 'Removed'
        ret['comment'] = ('Interface {0} removed'.format(interface))
    else:
        ret['comment'] = ('Interface {0} already removed'.format(interface))
    return ret
