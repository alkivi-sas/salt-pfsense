# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys
import logging

logger = logging.getLogger(__name__)


def present(name, identifier, who='root', mday='*', hour='*', month='*', wday='*', minute='*'):
    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    cron = __salt__['pfsense_cron.get_cron'](identifier, name)

    # Not present case
    if not cron:
        if __opts__['test']:
            ret['comment'] = 'Cron {0} is set to be created'.format(name)
            ret['result'] = None
            return ret

        # Add cron
        cron = __salt__['pfsense_cron.add_cron'](identifier,
                                                 name,
                                                 who,
                                                 mday,
                                                 hour,
                                                 month,
                                                 wday,
                                                 minute)
        ret['comment'] = 'Cron {0} was created'.format(name)
        ret['changes'] = cron
        return ret

    # Cron is present check changes
    new_cron = {
        'mday': mday,
        'hour': hour,
        'month': month,
        'wday': wday,
        'minute': minute,
        'command': name,
        'identifier': identifier,
        'who': who,
    }

    need_changes = False
    for key, value in new_cron.items():
        if key not in cron:
            logger.debug('Key {0} not in cron'.format(key))
            need_changes = True
            break
        elif value != cron[key]:
            logger.debug('Key {0} need change {1} vs {2}'.format(key, value, cron[key]))
            need_changes = True
            break

    if not need_changes:
        ret['comment'] = 'Cron {0} is already up to date'.format(name)
        return ret

    if __opts__['test']:
        ret['comment'] = 'Cron {0} would be update'.format(name)
        ret['changes'] = wanted_data
        return ret

    cron = __salt__['pfsense_cron.manage_cron'](identifier,
                                                name,
                                                who,
                                                mday,
                                                hour,
                                                month,
                                                wday,
                                                minute)
    ret['changes'] = cron
    ret['comment'] = 'Cron {0} was added'.format(name)
    return ret


def absent(name, identifier=None):
    '''
    '''

    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    if identifier is None:
        identifier = name

    cron = __salt__['pfsense_cron.get_cron'](identifier, name)

    # No present case
    if not cron:
        ret['comment'] = 'Cron {0} already absent'.format(name)
        return ret

    if __opts__['test']:
        ret['comment'] = 'Cron {0} set to be removed'.format(name)
        ret['result'] = None
        return ret

    cron = __salt__['pfsense_cron.remove_cron'](identifier, name)
    ret['comment'] = 'Cron {0} was removed'.format(name)
    return ret
