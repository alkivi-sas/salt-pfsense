# -*- coding: utf-8 -*-
"""
Module for running pfsense module via fauxapi
"""
from __future__ import absolute_import

# Import Python libs
import os
import re
import base64
import hashlib
import time
import binascii
import logging

# Import Salt libs
import salt.utils.files
import salt.utils.stringutils
import pfsense
from salt.exceptions import (
    CommandExecutionError,
    SaltInvocationError,
)

# Import 3rd-party libs
from salt.ext import six
from salt.ext.six.moves import range

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)


def list_crl(all_data=False):
    """Return dict of crls."""
    client = _get_client()
    config = client.config_get()

    ret = {}
    if 'crl' not in config:
        return ret

    for crl in config['crl']:
        if all_data:
            data = crl
        else:
            data = {
                'descr': crl['descr'],
                'caref': crl['caref'],
                'lifetime': crl['lifetime'],
                'serial': crl['serial'],
                'method': crl['method'],
            }
        ret[crl['refid']] = data
    return ret


def get_crl(refid, all_data=False):
    """Return specific crl."""
    crls = list_crl(all_data)
    if refid not in crls:
        raise CommandExecutionError('crl with id {0} not found'.format(refid))
    else:
        return crls[refid]


def get_crl_ca(refid, all_data=False):
    """Return CA for CRL."""
    crl = get_crl(refid, all_data)
    ca_refid = crl['caref']
    return get_ca(ca_refid, all_data)


def get_crl_revoked_list(refid, all_data=False):
    """Return a list of revoked cert."""
    crl = get_crl(refid, all_data=True)

    ret = {}
    if 'cert' not in crl:
        return ret

    for cert in crl['cert']:
        if all_data:
            data = cert
        else:
            data = {
                'reason': cert['reason'],
                'type': cert['type'],
                'revoke_time': cert['revoke_time'],
                'desc': cert['descr'],
            }
        ret[cert['refid']] = data
    return ret


def add_cert_to_crl(crlid, certid, reason=5):
    """Add a cert to a crl."""
    crl = get_crl(crlid)
    cert = get_cert(certid, all_data=True)
    revoked_list = get_crl_revoked_list(crlid)

    if certid in revoked_list:
        return 'Revocation already OK'

    # Base Settings
    cmd = ['php', '/opt/helpers/crl_revoke.php', crlid, certid, reason]

    result = __salt__['cmd.run_all'](cmd,
                                     python_shell=False)

    if result['retcode'] != 0:
        raise CommandExecutionError(result['stdout'])
    else:
        return 'Revocation OK'


def revoke_user_certificate(user, crlid=None, certid=None):
    """
    Revoke a user certificate

    Will check if a certificate matching user is present and revoke it.
    If multiple CRL is on the system, you can add crlid.
    """
    certs = list_cert()
    found_certid = None
    for foundcert_id, data in certs.items():
        if data['descr'].lower() == user:
            found_certid = foundcert_id
            break

    if certid:
        if certid not in certs:
            raise CommandExecutionError('no certificate with id {0}'.format(certid))
        else:
            found_certid = certid

    if not found_certid:
        raise CommandExecutionError('no certificate found with name {0}'.format(user))

    crls = list_crl()
    found_crlid = None
    if len(crls.keys()) == 0:
        raise CommandExecutionError('no CRL on the pfsense.')
    elif len(crls.keys()) == 1:
        found_crlid = crls.keys()[0]
    elif not crlid:
        raise CommandExecutionError('found multiple crl, please provide crlid')
    elif crlid not in crls:
        raise CommandExecutionError('crl with ref {0} not found'.format(crlid))
    else:
        found_crlid = crlid

    return add_cert_to_crl(found_crlid, found_certid)


def list_ca(all_data=False):
    """Return dict of ca."""
    client = _get_client()
    config = client.config_get()

    ret = {}
    if 'ca' not in config:
        return ret

    for ca in config['ca']:
        if all_data:
            data = ca
        else:
            data = {
                'descr': ca['descr'],
                'serial': ca['serial'],
            }
        ret[ca['refid']] = data
    return ret


def get_ca(refid, all_data=False):
    """Return specific crl."""
    cas = list_ca(all_data)
    if refid not in cas:
        raise CommandExecutionError('ca with id {0} not found'.format(refid))
    else:
        return cas[refid]


def list_cert(all_data=False):
    """Return dict of cert."""
    client = _get_client()
    config = client.config_get()

    ret = {}
    if 'cert' not in config:
        return ret

    for cert in config['cert']:
        if 'descr' not in cert:
            continue

        if all_data:
            data = cert
        else:
            data = {
                'descr': cert['descr'],
            }
            if 'type' in cert:
                data['type'] = cert['type']
            if 'caref' in cert:
                data['caref'] = cert['caref']
        ret[cert['refid']] = data
    return ret


def get_cert(refid, all_data=False):
    """Return specific crl."""
    certs = list_cert(all_data)
    if refid not in certs:
        raise CommandExecutionError('cert with id {0} not found'.format(refid))
    else:
        return certs[refid]


def list_cert_with_status():
    """Return a dict with certs."""

    client = _get_client()
    config = client.config_get()

    users_certificates = {}
    for user in config['system']['user']:
        uid = user['uid']
        cert = user.get('cert', None)
        if cert:
            users_certificates[cert] = dict(user)
    return users_certificates

    certs = list_cert(all_data=True)
    crl = list_crl(all_data=True)

    test = {'users': users_certificates, 'certs':certs, 'crl': crl}
    return test
