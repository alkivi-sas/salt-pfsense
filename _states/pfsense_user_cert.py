# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys
import logging

# Import 3rd-party libs
from salt.ext import six

logger = logging.getLogger(__name__)


def present(name, caref=None):

    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    # Test user exist ?
    user = __salt__['pfsense_user.get_user'](name)
    if not user:
        ret['result'] = False
        ret['comment'] = 'User {0} does not exist'.format(name)
        return ret

    # Fetch ca and see if only one
    if caref is None:
        cas = __salt__['pfsense_certificate.list_ca']()
        if len(cas.keys()) == 1:
            caref = cas.keys()[0]
        else:
            ret['result'] = False
            ret['comment'] = 'Unable to find a CA, please add caref parameter'
            return ret

    # Test ca exist ?
    ca = __salt__['pfsense_certificate.get_ca'](caref)
    if not ca:
        ret['result'] = False
        ret['comment'] = 'CA {0} does not exist'.format(caref)
        return ret

    # Test if already got a certificate ?
    existing_cert = None
    if 'cert' in user:
        for certid in user['cert']:
            cert = __salt__['pfsense_certificate.get_cert'](certid)
            if cert['caref'] == caref:
                existing_cert = cert
                break

    # TODO : check if revoked ?
    if existing_cert:
        ret['comment'] = 'A certificate already exist for user {0}'.format(name)
        return ret

    # Create a certificate
    if __opts__['test']:
        ret['comment'] = 'User certificate would have been created'
        ret['result'] = None
        return ret

    cert, error = __salt__['pfsense_certificate.add_user_certificate'](name, caref)
    if not cert:
        ret['result'] = False
        ret['comment'] = error
    else:
        ret['comment'] = 'Certificate created'
        ret['changes'] = cert
        return ret


def revoked(name, crlid=None, certid=None):
    '''
    '''

    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    user = __salt__['pfsense_user.get_user'](name)

    # No user : warning
    # No crl : warning
    # No certid to user : warning
    # Revoke
    return ret

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
