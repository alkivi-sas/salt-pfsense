# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys


def present(name):
    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_sshguard_whitelist.has_ip'](name)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'IP is set to be created'
            return ret
        else:
            ret['comment'] = 'IP is already present'
        return ret

    data = __salt__['pfsense_sshguard_whitelist.add_ip'](name)

    if is_present: 
        ret['comment'] = ('IP {0} was already present'.format(name))
    else:
        ret['changes'][name] = 'New'
        ret['comment'] = ('IP {0} added'.format(name))
    return ret


def absent(name):
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_sshguard_whitelist.has_ip'](name)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'IP is not present'
        else:
            ret['comment'] = 'IP set to be removed'
        return ret

    data = __salt__['pfsense_sshguard_whitelist.rm_ip'](name)

    if is_present: 
        ret['changes'][name] = 'Removed'
        ret['comment'] = ('IP {0} removed'.format(name))
    else:
        ret['comment'] = ('IP {0} already removed'.format(name))
    return ret
