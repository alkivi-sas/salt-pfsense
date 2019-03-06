# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys

# Import 3rd-party libs
from salt.ext import six


def present(
        name,
        target,
        type,
        descr='',
        detail=''):
    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    targets = [target]
    if isinstance(target, list):
        targets = target

    is_present = __salt__['pfsense_aliases.get_target'](name)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Alias is set to be created'
            return ret
        is_ok = __salt__['pfsense_aliases.has_target'](name, target)
        if is_ok:
            ret['comment'] = 'Alias is already OK'
        else:
            ret['comment'] = 'Alias is set to be updated'
        return ret

    data = __salt__['pfsense_aliases.set_target'](
            name,
            target,
            type=type,
            descr=descr,
            detail=detail)

    real_targets = ' '.join(targets)
    if is_present: 
        is_ok = __salt__['pfsense_aliases.has_target'](name, target)
        if is_ok:
            ret['comment'] = ('Alias {0} was already OK'.format(name))
        else:
            ret['changes'][name] = 'Updated'
            ret['comment'] = ('Alias {0} updated to {1}'.format(name, real_targets))
    else:
        ret['changes'][name] = 'New'
        ret['comment'] = ('Alias {0} of type {1} set to {2}'.format(name, type, real_targets))
    return ret


def absent(name):
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_aliases.get_target'](name)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Alias is not present'
        else:
            ret['comment'] = 'Alias set to be removed'
        return ret

    data = __salt__['pfsense_aliases.rm_alias'](name)

    if is_present: 
        ret['changes'][name] = 'Removed'
        ret['comment'] = ('Alias {0} removed'.format(name))
    else:
        ret['comment'] = ('Alias {0} already removed'.format(name))
    return ret
