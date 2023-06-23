# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys
import logging

logger = logging.getLogger(__name__)


def present(name,
            protocol,
            target,
            interface,
            local_port,
            disabled=False,
            source=None,
            destination=None,
            index=0):
    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}


    rule = __salt__['pfsense_nat_rule.get_rule'](name,
                                                 protocol,
                                                 target,
                                                 interface,
                                                 local_port,
                                                 disabled,
                                                 source,
                                                 destination)

    # Not present case
    if not rule:
        if __opts__['test']:
            ret['comment'] = 'Rule {0} is set to be created'.format(name)
            ret['result'] = None
            return ret

        # Add rule
        rule = __salt__['pfsense_nat_rule.add_rule'](name,
                                                     protocol,
                                                     target,
                                                     interface,
                                                     local_port,
                                                     disabled,
                                                     source,
                                                     destination,
                                                     index)
                                            
        ret['comment'] = 'Rule {0} was created'.format(name)
        ret['changes'] = rule
        return ret

    ret['comment'] = 'Rule is already present'.format(name)
    return ret


def absent(name,
            protocol,
            target,
            interface,
            local_port,
            disabled=False,
            source=None,
            destination=None):
    '''
    '''

    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    rule = __salt__['pfsense_nat_rule.get_rule'](name,
                                                 protocol,
                                                 target,
                                                 interface,
                                                 local_port,
                                                 disabled,
                                                 source,
                                                 destination)

    # No present case
    if not rule:
        ret['comment'] = 'Rule {0} was already absent'.format(name)
        return ret

    if __opts__['test']:
        ret['comment'] = 'Rule {0} is set to be removed'.format(name)
        ret['result'] = None
        return ret

    rule = __salt__['pfsense_nat_rule.rm_rule'](name,
                                                protocol,
                                                target,
                                                interface,
                                                local_port,
                                                disabled,
                                                source,
                                                destination)
    ret['comment'] = 'Rule {0} was removed'.format(name)
    return ret
