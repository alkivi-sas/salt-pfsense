# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys
import logging

logger = logging.getLogger(__name__)


def present(name, gateway=None):
    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    dns = __salt__['pfsense_dns.get_dns'](name)

    # Not present case
    if not dns:
        if __opts__['test']:
            if gateway is not None:
                ret['comment'] = 'DNS {0} is set to be created with gateway {1}'.format(name, gateway)
            else:
                ret['comment'] = 'DNS {0} is set to be created'.format(name)
            ret['result'] = None
            return ret

        # Add dns
        dns = __salt__['pfsense_dns.add_dns'](name, gateway)
        if not dns:
            ret['comment'] = 'DNS {0} failed to be added'.format(name)
            ret["result"] = False
            return ret
        else:
            changes = dns["changes"]
            if changes:
                ret['comment'] = 'DNS {0} was created'.format(name)
                ret['changes'] = changes
            else:
                ret['comment'] = 'DNS {0} has no changes'.format(name)

        return ret

    # DNS is present check changes
    changes = __salt__["pfsense_dns.need_changes"](name, gateway)
    if changes is None:
        ret['comment'] = 'DNS {0} is already up to date'.format(name)
        return ret

    if __opts__['test']:
        ret['comment'] = 'DNS {0} would be update'.format(name)
        ret['changes'] = changes
        return ret

    dns = __salt__['pfsense_dns.add_dns'](name, gateway)
    if not dns:
        ret['comment'] = 'DNS {0} failed to be added'.format(name)
        ret["result"] = False
        return ret
    else:
        changes = dns["changes"]
        if changes:
            ret['comment'] = 'DNS {0} was updated'.format(name)
            ret['changes'] = changes
        else:
            ret['comment'] = 'DNS {0} has no changes'.format(name)
    return ret


def absent(name):
    '''
    '''

    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    dns = __salt__['pfsense_dns.get_dns'](name)

    # No present case
    if not dns:
        ret['comment'] = 'DNS {0} already absent'.format(name)
        return ret

    if __opts__['test']:
        ret['comment'] = 'DNS {0} set to be removed'.format(name)
        ret['result'] = None
        return ret

    dns = __salt__['pfsense_dns.del_dns'](name)
    if not dns:
        ret['comment'] = 'DNS {0} failed to be removed'.format(name)
        ret["result"] = False
        return ret
    else:
        changes = dns["changes"]
        if changes:
            ret['comment'] = 'DNS {0} was deleted'.format(name)
            ret['changes'] = changes
        else:
            ret['comment'] = 'DNS {0} has no changes'.format(name)
    return ret
