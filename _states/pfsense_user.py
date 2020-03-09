# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys
import logging

# Import 3rd-party libs
from salt.ext import six

logger = logging.getLogger(__name__)


def present(
        name,
        password=None,
        descr=None,
        expires=None,
        dashboardcolumns=None,
        authorizedkeys=None,
        ipsecpsk=None,
        webguicss=None,
        disabled=None,
        priv=None):
    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    wanted_data = {}
    if password is not None:
        wanted_data['password'] = password
    if descr is not None:
        wanted_data['descr'] = descr
    if expires is not None:
        wanted_data['expires'] = expires
    if dashboardcolumns is not None:
        wanted_data['dashboardcolumns'] = dashboardcolumns
    if authorizedkeys is not None:
        wanted_data['authorizedkeys'] = authorizedkeys
    if ipsecpsk is not None:
        wanted_data['ipsecpsk'] = ipsecpsk
    if webguicss is not None:
        wanted_data['webguicss'] = webguicss
    if disabled is not None:
        wanted_data['disabled'] = disabled
    if priv is not None:
        wanted_data['priv'] = priv


    user = __salt__['pfsense_user.get_user'](name)

    # Not present case
    if not user:
        if __opts__['test']:
            ret['comment'] = 'User {0} is set to be created'.format(name)
            ret['result'] = None
            return ret

        # Add user
        user = __salt__['pfsense_user.add_user'](name, attributes=wanted_data)
        ret['comment'] = 'User {0} was created'.format(name)
        ret['changes'] = user
        return ret

    # User is present check changes
    need_changes = False
    for key, value in wanted_data.items():
        if key == 'password':
            logger.debug('password change was requested')
            need_changes = True
            break
        elif key == 'disabled':
            if value:
                if key not in user:
                    logger.debug('disabled needs update')
                    need_changes = True
                    break
            else:
                if key in user:
                    logger.debug('disabled needs update')
                    need_changes = True
                    break
        else:
            if key not in user:
                logger.debug('Key {0} not in user'.format(key))
                need_changes = True
                break
            elif value != user[key]:
                logger.debug('Key {0} need change {1} vs {2}'.format(key, value, user[key]))
                need_changes = True
                break

    if not need_changes:
        ret['comment'] = 'User {0} is already up to date'.format(name)
        return ret

    if __opts__['test']:
        ret['comment'] = 'User {0} would be update'.format(name)
        ret['changes'] = wanted_data
        return ret

    user = __salt__['pfsense_user.manage_user'](name, attributes=wanted_data)
    ret['changes'] = user
    ret['comment'] = 'User {0} was added'.format(name)
    return ret


def absent(name):
    '''
    '''

    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    user = __salt__['pfsense_user.get_user'](name)

    # No present case
    if not user:
        ret['comment'] = 'User {0} already absent'.format(name)
        return ret

    if __opts__['test']:
        ret['comment'] = 'User {0} set to be removed'.format(name)
        ret['result'] = None
        return ret

    user = __salt__['pfsense_user.remove_user'](name)
    ret['comment'] = 'User {0} was removed'.format(name)
    return ret
