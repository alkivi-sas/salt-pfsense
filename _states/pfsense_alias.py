# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys


def present(
        name,
        target,
        type,
        descr='',
        detail='',
        url=None,
        updatefreq=None):
    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    targets = [str(target)]
    if isinstance(target, list):
        targets = [str(x) for x in target]

    is_present = __salt__['pfsense_alias.get_target'](name)

    # Test if needs changes
    changes = {}
    if is_present:
        is_target_ok = __salt__['pfsense_alias.has_target'](name, targets)
        if not is_target_ok:
            changes['target'] = targets

        if url is not None:
            current_url = __salt__['pfsense_alias.get_url'](name)
            if url != current_url:
                changes['url'] = url

        if updatefreq is not None:
            current_updatefreq = __salt__['pfsense_alias.get_updatefreq'](name)
            if updatefreq != current_updatefreq:
                changes['updatefreq'] = updatefreq

    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Alias is set to be created'
            return ret
        elif not changes:
            ret['comment'] = 'Alias is already OK'
        else:
            ret['changes'][name] = changes
            ret['comment'] = 'Alias is set to be updated'
        return ret

    data = __salt__['pfsense_alias.set_target'](
            name,
            target,
            type=type,
            descr=descr,
            detail=detail,
            url=url,
            updatefreq=updatefreq,
            )

    if is_present:
        if not changes:
            ret['comment'] = 'Alias {0} was already OK'.format(name)
        else:
            ret['changes'][name] = changes
            ret['comment'] = 'Alias {0} updated !'.format(name)
    else:
        ret['comment'] = 'Alias {0} of type {1} created'.format(name, type)
    return ret


def absent(name):
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_alias.get_target'](name)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Alias is not present'
        else:
            ret['comment'] = 'Alias set to be removed'
        return ret

    data = __salt__['pfsense_alias.rm_alias'](name)

    if is_present:
        ret['changes'][name] = 'Removed'
        ret['comment'] = ('Alias {0} removed'.format(name))
    else:
        ret['comment'] = ('Alias {0} already removed'.format(name))
    return ret
