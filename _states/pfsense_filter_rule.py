# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys
import logging

# Import 3rd-party libs
from salt.ext import six

logger = logging.getLogger(__name__)


def present(name, interface, index=0, **kwargs):
    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    rule = __salt__['pfsense_filter_rule.get_rule'](name, interface)

    # Not present case
    if not rule:
        if __opts__['test']:
            ret['comment'] = 'Rule {0} is set to be created'.format(name)
            ret['result'] = None
            return ret

        # Add rule
        kwargs['descr'] = name
        kwargs['interface'] = interface
        rule = __salt__['pfsense_filter_rule.add_rule'](**kwargs)
        ret['comment'] = 'Rule {0} was created'.format(name)
        ret['changes'] = rule
        return ret

    ret['comment'] = 'Rule is already present'.format(name)
    return ret


def absent(name, interface):
    '''
    '''

    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    rule = __salt__['pfsense_filter_rule.get_rule'](name, interface)

    # No present case
    if not rule:
        ret['comment'] = 'Rule {0} was already absent'.format(name)
        return ret

    if __opts__['test']:
        ret['comment'] = 'Rule {0} is set to be removed'.format(name)
        ret['result'] = None
        return ret

    rule = __salt__['pfsense_filter_rule.rm_rule'](name, interface)
    ret['comment'] = 'Rule {0} was removed'.format(name)
    return ret
