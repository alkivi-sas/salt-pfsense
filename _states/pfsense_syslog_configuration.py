# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys

# Import 3rd-party libs
from salt.ext import six


def present(
        name,
        value):
    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    current_value = __salt__['pfsense_syslog_configuration.get_setting'](name)
    if __opts__['test']:
        if value != current_value:
            ret['result'] = None
            ret['comment'] = 'Key {0} is set to be updated from {1} to {2}'.format(name, current_value, value)
        else:
            ret['comment'] = 'Key {0} is already OK'.format(name)
        return ret

    if current_value == value:
        ret['comment'] = 'No change needed for key {0}'.format(name)
        return ret

    data = __salt__['pfsense_syslog_configuration.set_setting'](name, value)
    ret['changes'][name] = 'Updated'
    ret['comment'] = 'Key {0} set to {1}'.format(name, value)
    return ret
