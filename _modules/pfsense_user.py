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


def _sync_ha():
    cmd = ['/etc/rc.filter_synchronize']
    __salt__['cmd.run_all'](cmd, python_shell=False)

def list_users():
    client = _get_client()
    config = client.config_get()

    response_data = {}
    index = 0
    for user in config['system']['user']:
        user['userid'] = index
        response_data[user['name']] = user
        del(response_data[user['name']]['name'])
        index += 1
    return response_data


def get_user(username):
    user_index, user = _get_entity('user', username)
    if user_index is None:
        return None, None
    return user_index, user


def add_user(username, attributes={}):
    client = _get_client()
    config = client.config_get()

    user_index, user = _get_entity('user', username)
    if user_index is not None:
        raise CommandExecutionError('user {0} already exists'.format(username))

    valid_attributes = ['password','descr','expires','dashboardcolumns','authorizedkeys','ipsecpsk','webguicss','disabled','priv']

    user = {
        'scope': 'user',
        'bcrypt-hash': 'no-password-set',
        'descr': '',
        'name': username,
        'expires': '',
        'dashboardcolumns': '2',
        'authorizedkeys': '',
        'ipsecpsk': '',
        'webguicss': 'pfSense.css',
        'uid': _get_next_id('uid'),
    }

    for attribute, value in attributes.items():
        if attribute not in valid_attributes:
            raise CommandExecutionError('unsupported attribute type', attribute)

        if attribute == 'disabled':
            if value is True:
                user[attribute] = ''
            else:
                if attribute in user:
                    del(user[attribute])
        elif attribute == 'password':
            user['bcrypt-hash'] = value
        else:
            if len(value) == 0 and attribute in user:
                del(user[attribute])
            elif len(value) > 0:
                user[attribute] = value

    patch_system_user = {
        'system': {
            'user': config['system']['user']
        }
    }
    patch_system_user['system']['user'].append(user)

    response = client.config_patch(patch_system_user)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add user', response['message'])

    _increment_next_id('uid')
    _sync_ha()

    uid = int(user['uid'])
    shell = '/sbin/tcsh'
    if 'disabled' in user:
        shell = '/sbin/nologin'
    fullname = user['descr']
    createhome=False
    gid=65534
    system_user = __salt__['user.add'](username, uid=uid, gid=gid, shell=shell, fullname=fullname, createhome=createhome)

    if user['bcrypt-hash'].startswith('$'):
        system_user = __salt__['shadow.set_password'](username, user['bcrypt-hash'])

    return user

def manage_user(username, attributes):
    client = _get_client()
    config = client.config_get()

    valid_attributes = ['password','descr','expires','dashboardcolumns','authorizedkeys','ipsecpsk','webguicss','disabled','priv']

    user_index, user = _get_entity('user', username)
    if user_index is None:
        raise CommandExecutionError('user {0} does not exist'.format(username))

    if type(attributes) != dict:
        raise CommandExecutionError('attributes is incorrect type')

    for attribute, value in attributes.items():
        if attribute not in valid_attributes:
            raise CommandExecutionError('unsupported attribute type', attribute)

        if attribute == 'disabled':
            if value is True:
                user[attribute] = ''
            else:
                if attribute in user:
                    del(user[attribute])
        elif attribute == 'password':
            user['bcrypt-hash'] = value
        else:
            if len(value) == 0 and attribute in user:
                del(user[attribute])
            elif len(value) > 0:
                user[attribute] = value

    patch_system_user = {
        'system': {
            'user': config['system']['user']
        }
    }
    patch_system_user['system']['user'][user_index] = user

    response = client.config_patch(patch_system_user)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to manage user', response['message'])
    _sync_ha()

    if 'descr' in attributes:
        descr = attributes['descr']
        system_user = __salt__['user.chfullname'](username, descr)

    if 'disabled' in attributes:
        disabled = attributes['disabled']
        if disabled:
            system_user = __salt__['user.chshell'](username, '/sbin/nologin')
        else:
            system_user = __salt__['user.chshell'](username, '/sbin/tcsh')

    if 'password' in attributes:
        if user['bcrypt-hash'].startswith('$'):
            system_user = __salt__['shadow.set_password'](username, user['bcrypt-hash'])

    return user

def add_cert(username, refid):
    """Add a certificate to a user."""
    client = _get_client()
    config = client.config_get()

    user_index, user = _get_entity('user', username)
    if user_index is None:
        raise CommandExecutionError('user {0} does not exist'.format(username))

    if 'cert' in user:
        user['cert'].append(refid)
    else:
        user['cert'] = [refid]

    patch_system_user = {
        'system': {
            'user': config['system']['user']
        }
    }
    patch_system_user['system']['user'][user_index] = user

    response = client.config_patch(patch_system_user)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to manage user', response['message'])
    _sync_ha()
    return True


def export_openvpn_config(username, addr, vpnid=None, caref=None, conf_type='confzip'):
    """Export localy in /tmp a openvpn file."""

    # Check username exists
    userid, user = get_user(username)
    if not user:
        raise CommandExecutionError('Unable to find user {0}'.format(username))

    # Check openvpn vpnid
    servers = __salt__['pfsense_openvpn.list_servers']()
    server = None
    if vpnid:
        vpnid=str(vpnid)
        if vpnid not in servers:
            raise CommandExecutionError('Server with id {0} not found'.format(vpnid))
        server = servers[vpnid]
    else:
        if len(servers.keys()) == 1:
            vpnid = list(servers.keys())[0]
            server = servers[vpnid]
        else:
            raise CommandExecutionError('Multiple VPN server found, please specify vpnid parameter.')

    # Check caref
    cas = __salt__['pfsense_certificate.list_ca']()
    if caref:
        if caref not in cas:
            raise CommandExecutionError('CA {0} not found on this system'.format(caref))
    else:
        caref = server['caref']

    # Check that username have a cert with ca
    if 'cert' not in user:
        raise CommandExecutionError('User {0} does not have any certificates'.format(username))

    wanted_certid = None
    for certid in user['cert']:
        cert = __salt__['pfsense_certificate.get_cert'](certid)
        if not cert:
            raise CommandExecutionError('Weird shit, user have cert {0} but it does not exists on system'.format(certid))
        if cert['caref'] == caref:
            wanted_certid = certid
            break

    if not wanted_certid:
        raise CommandExecutionError('Unable to find a user certificate')

    cert_index = __salt__['pfsense_certificate.get_cert_index'](certid)
    if not cert_index:
        raise CommandExecutionError('Unable to get cert index.')

    # Check that ca match vpn caref
    if server['caref'] != caref:
        raise CommandExecutionError('OpenVPN server CA {0} does not match wanted CA {1}'.format(server['caref'], caref))

    # Launch generation
    cmd = ['php', '/opt/helpers/export_openvpn_config.php', vpnid, cert_index, caref, addr, conf_type]

    result = __salt__['cmd.run_all'](cmd,
                                     python_shell=False)

    # Return path
    if result['retcode'] != 0:
        raise CommandExecutionError(result['stdout'])
    return result['stdout']


def remove_user(username):
    client = _get_client()
    config = client.config_get()

    user_index, user = _get_entity('user', username)
    if user_index is None:
        raise CommandExecutionError('user does not exist', username)

    patch_system_user = {
        'system': {
            'user': config['system']['user']
        }
    }
    del(patch_system_user['system']['user'][user_index])

    response = client.config_patch(patch_system_user)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to remove user', response['message'])
    _sync_ha()

    system_user = __salt__['user.delete'](username, remove=True, force=True)

    return True

# group functions
# =========================================================================

def list_groups():
    client = _get_client()
    config = client.config_get()

    response_data = {}
    for group in config['system']['group']:
        response_data[group['name']] = group
        del(response_data[group['name']]['name'])
    return response_data

def add_group(groupname):
    client = _get_client()
    config = client.config_get()

    group_index, group = _get_entity('group', groupname)
    if group_index is not None:
        raise CommandExecutionError('group already exists', groupname)

    group = {
        'scope': 'local',
        'description': '',
        'name': groupname,
        'gid': _get_next_id('gid'),
    }

    patch_system_group = {
        'system': {
            'group': config['system']['group']
        }
    }
    patch_system_group['system']['group'].append(group)

    response = client.config_patch(patch_system_group)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add group', response['message'])

    _increment_next_id('gid')
    _sync_ha()

    return group

def manage_group(groupname, attributes):
    client = _get_client()
    config = client.config_get()

    valid_attributes = ['description','member','priv']

    group_index, group = _get_entity('group', groupname)
    if group_index is None:
        raise CommandExecutionError('group does not exist', groupname)

    if type(attributes) != dict:
        raise CommandExecutionError('attributes is incorrect type')

    for attribute, value in attributes.items():
        if attribute not in valid_attributes:
            raise CommandExecutionError('unsupported attribute type', attribute)

        if attribute == 'member':
            if type(value) != list:
                raise CommandExecutionError('member attribute is incorrect type')
        elif attribute == 'priv':
            if type(value) != list:
                raise CommandExecutionError('priv attribute is incorrect type')

        if len(value) == 0 and attribute in group:
            del(group[attribute])
        elif len(value) > 0:
            group[attribute] = value

    patch_system_group = {
        'system': {
            'group': config['system']['group']
        }
    }
    patch_system_group['system']['group'][group_index] = group

    response = client.config_patch(patch_system_group)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to manage group', response['message'])
    _sync_ha()

    return group

def remove_group(groupname):
    client = _get_client()
    config = client.config_get()

    group_index, group = _get_entity('group', groupname)
    if group_index is None:
        raise CommandExecutionError('group does not exist', groupname)

    patch_system_group = {
        'system': {
            'group': config['system']['group']
        }
    }
    del(patch_system_group['system']['group'][group_index])

    response = client.config_patch(patch_system_group)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to remove group', response['message'])
    _sync_ha()

    return group

# internal helper functions
# =========================================================================

def _get_entity(entity_type, entity_name):
    client = _get_client()
    config = client.config_get()

    entity = None
    entity_index = 0
    for entity_data in config['system'][entity_type]:
        if entity_data['name'] == entity_name:
            entity = entity_data
            break
        entity_index += 1

    if entity is None:
        return None, None

    return entity_index, entity

def _get_next_id(id_type):
    client = _get_client()
    config = client.config_get()

    id_name = 'next{}'.format(id_type)
    return config['system'][id_name]

def _increment_next_id(id_type):
    client = _get_client()
    config = client.config_get()

    id_name = 'next{}'.format(id_type)
    next_id = int(_get_next_id(id_type)) + 1
    patch_system_nextid = {
        'system': {
            id_name: str(next_id)
        }
    }
    response = client.config_patch(patch_system_nextid)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to increment the nextid', id_type)
    return next_id
