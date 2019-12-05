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

def list_users():
    client = _get_client()
    config = client.config_get()

    response_data = {}
    for user in config['system']['user']:
	response_data[user['name']] = user
	del(response_data[user['name']]['name'])
    return response_data


def get_user(username):
    user_index, user = _get_entity('user', username)
    if user_index is None:
        return None
    return user


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
	    user['bcrypt-hash'] = bcrypt.hashpw(value.encode('utf8'), bcrypt.gensalt()).decode('utf8')
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
	    user['bcrypt-hash'] = bcrypt.hashpw(value.encode('utf8'), bcrypt.gensalt()).decode('utf8')
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

    return user

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
