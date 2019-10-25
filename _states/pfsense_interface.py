# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys

# Import 3rd-party libs
from salt.ext import six


def present(
        interface, 
        ifname,
        ipaddr,
        subnet,
        descr,
        enable=True,
        spoofmac='',
        ipaddrv6=None,
        subnetv6=None,
        gateway=None,
        blockbogons=None,
        blockpriv=None):
    '''
    '''

    ret = {'name': interface,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_interface.get_interface'](interface)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Interface {0} is set to be created'.format(interface)
            return ret
        is_ok = __salt__['pfsense_interface.has_interface'](interface)
        if is_ok:
            ret['comment'] = 'Interface is already OK'
        else:
            ret['comment'] = 'Interface is set to be updated'
        return ret

    data = __salt__['pfsense_interface.set_interface'](
            interface,
            tag,
            descr=descr,
            pcp=pcp)

    if is_present: 
            ret['changes'][interfaceif] = 'Updated'
            ret['comment'] = ('Interface {0} updated'.format(interfaceif))
    else:
        ret['changes'][interfaceif] = 'New'
        ret['comment'] = ('Interface {0} added'.format(interfaceif))
    return ret


def absent(name, interface, tag):
    interfaceif = '{0}.{1}'.format(interface, tag)

    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_interface.get_interface'](interface, tag)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Interface {0} is not present'.format(interfaceif)
        else:
            ret['comment'] = 'Interface {0} set to be removed'.format(interfaceif)
        return ret

    data = __salt__['pfsense_interface.rm_interface'](interface, tag)

    if is_present: 
        ret['changes'][interfaceif] = 'Removed'
        ret['comment'] = ('Interface {0} removed'.format(interfaceif))
    else:
        ret['comment'] = ('Interface {0} already removed'.format(interfaceif))
    return ret
