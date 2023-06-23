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

    is_present = __salt__['pfsense_althostname.has_hostname'](name)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Hostname is set to be created'
            return ret
        else:
            ret['comment'] = 'Hostname is already present'
        return ret

    data = __salt__['pfsense_althostname.add_hostname'](name)

    if is_present: 
        ret['comment'] = ('Hostname {0} was already present'.format(name))
    else:
        ret['changes'][name] = 'New'
        ret['comment'] = ('Hostname {0} added'.format(name))
    return ret


def absent(name):
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_althostname.has_hostname'](name)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Hostname is not present'
        else:
            ret['comment'] = 'Hostname set to be removed'
        return ret

    data = __salt__['pfsense_althostname.rm_hostname'](name)

    if is_present: 
        ret['changes'][name] = 'Removed'
        ret['comment'] = ('Hostname {0} removed'.format(name))
    else:
        ret['comment'] = ('Hostname {0} already removed'.format(name))
    return ret
