# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys

# Import 3rd-party libs
from salt.ext import six


def present(
        name,
        interface,
        tag,
        descr=None,
        pcp=None):
    '''
    '''
    vlanif = '{0}.{1}'.format(interface, tag)

    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_vlan.get_vlan'](interface, tag)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'VLAN is set to be created'
            return ret
        is_ok = __salt__['pfsense_vlan.has_vlan'](interface, vlan)
        if is_ok:
            ret['comment'] = 'VLAN is already OK'
        else:
            ret['comment'] = 'VLAN is set to be updated'
        return ret

    data = __salt__['pfsense_vlan.set_vlan'](
            interface,
            tag,
            descr=descr,
            pcp=pcp)

    if is_present: 
            ret['changes'][vlanif] = 'Updated'
            ret['comment'] = ('VLAN {0} updated'.format(vlanif))
    else:
        ret['changes'][vlanif] = 'New'
        ret['comment'] = ('VLAN {0} added'.format(vlanif))
    return ret


def absent(name, interface, tag):
    vlanif = '{0}.{1}'.format(interface, tag)

    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_vlan.get_vlan'](interface, tag)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'VLAN {0} is not present'.format(vlanif)
        else:
            ret['comment'] = 'VLAN {0} set to be removed'.format(vlanif)
        return ret

    data = __salt__['pfsense_vlan.rm_vlan'](interface, tag)

    if is_present: 
        ret['changes'][vlanif] = 'Removed'
        ret['comment'] = ('VLAN {0} removed'.format(vlanif))
    else:
        ret['comment'] = ('VLAN {0} already removed'.format(vlanif))
    return ret
