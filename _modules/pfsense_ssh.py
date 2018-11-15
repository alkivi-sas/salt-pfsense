# -*- coding: utf-8 -*-
"""
Module for running pfsense module via fauxapi
"""
from __future__ import absolute_import

# Import Python libs
import os
import re
import base64
import logging

# Import Salt libs
import pfsense
from salt.exceptions import (
    CommandExecutionError,
)


logger = logging.getLogger(__name__)

def __virtual__():
    if __salt__['file.file_exists']('/etc/pf.os'):
        return True
    else:
        return False

def _refine_enc(enc):
    '''
    Return the properly formatted ssh value for the authorized encryption key
    type. ecdsa defaults to 256 bits, must give full ecdsa enc schema string
    if using higher enc. If the type is not found, raise CommandExecutionError.
    '''

    rsa = ['r', 'rsa', 'ssh-rsa']
    dss = ['d', 'dsa', 'dss', 'ssh-dss']
    ecdsa = ['e', 'ecdsa', 'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384',
             'ecdsa-sha2-nistp256']
    ed25519 = ['ed25519', 'ssh-ed25519']

    if enc in rsa:
        return 'ssh-rsa'
    elif enc in dss:
        return 'ssh-dss'
    elif enc in ecdsa:
        # ecdsa defaults to ecdsa-sha2-nistp256
        # otherwise enc string is actual encoding string
        if enc in ['e', 'ecdsa']:
            return 'ecdsa-sha2-nistp256'
        return enc
    elif enc in ed25519:
        return 'ssh-ed25519'
    else:
        raise CommandExecutionError(
            'Incorrect encryption key type \'{0}\'.'.format(enc)
        )


def _format_auth_line(key, enc, comment, options):
    '''
    Properly format user input.
    '''
    line = ''
    if options:
        line += '{0} '.format(','.join(options))
    line += '{0} {1} {2}\n'.format(enc, key, comment)
    return line


def _decode_keys(raw):
    '''base64 decode and then split with \r\n.'''
    ret = {}
    keyre = re.compile(r'^(.*?)\s?((?:ssh\-|ecds)[\w-]+\s.+)$')

    keys = base64.b64decode(raw).split('\r\n')
    for key in keys:
        if key.startswith('#'):
            # Commented Line
            continue

        # get "{options} key"
        search = re.search(keyre, key)
        if not search:
            # not an auth ssh key, perhaps a blank k
            continue

        opts = search.group(1)
        comps = search.group(2).split()

        if len(comps) < 2:
            # Not a valid key
            continue

        if opts:
            # It has options, grab them
            options = opts.split(',')
        else:
            options = []

        enc = comps[0]
        k = comps[1]
        comment = ' '.join(comps[2:])

        ret[k] = {'enc': enc,
                  'comment': comment,
                  'options': options}
    return ret


def _encode_keys(keys):
    '''\r\n join and then base64 encode.'''
    correct_keys = []

    for key, config in keys.items():
        cline = _format_auth_line(key,
                                  config['enc'],
                                  config['comment'],
                                  config['options'])
        correct_keys.append(cline)

    to_put_keys = '\r\n'.join(correct_keys)
    return base64.b64encode(to_put_keys)


def _get_user(user, config):
    '''Return the correct user or rise an Exception.'''
    users = config['system']['user']
    correct_user = None
    for u in users:
        if u['name'] == user:
            correct_user = u
            break

    if not correct_user:
        raise CommandExecutionError('Unable to get user {0}'.format(user))
    else:
        return correct_user


def auth_keys(user, config='.ssh/authorized_keys', fingerprint_hash_type=None):
    '''
    Return the authorized keys for users

    CLI Example:

    .. code-block:: bash

        salt '*' ssh.auth_keys root
    '''
    apikey = 'PFFA{0}'.format(__salt__['alkivi.password']('apikey', 'api', '30'))
    apisecret = __salt__['alkivi.password']('apisecret', 'api', '64')
    client = pfsense.FauxapiLib(debug=True, apikey=apikey, apisecret=apisecret)
    config = client.config_get()
    correct_user = _get_user(user, config)
    authorizedkeys = correct_user['authorizedkeys']
    keys = _decode_keys(authorizedkeys)

    return keys


def _get_config_file(user, config):
    '''
    Get absolute path to a user's ssh_config.
    '''
    uinfo = __salt__['user.info'](user)
    if not uinfo:
        raise CommandExecutionError('User \'{0}\' does not exist'.format(user))
    home = uinfo['home']
    config = _expand_authorized_keys_path(config, user, home)
    if not os.path.isabs(config):
        config = os.path.join(home, config)
    return config


def check_key(
        user,
        key,
        enc='ssh-rsa',
        comment='',
        options=None,
        config='.ssh/authorized_keys',
        cache_keys=None):
    '''
    Check to see if a key needs updating, returns "update", "add" or "exists"

    CLI Example:

    .. code-block:: bash

        salt '*' ssh.check_key <user> <key> <enc> <comment> <options>
    '''
    enc = _refine_enc(enc)
    current = auth_keys(user)
    nline = _format_auth_line(key, enc, comment, options)

    if key in current:
        cline = _format_auth_line(key,
                                  current[key]['enc'],
                                  current[key]['comment'],
                                  current[key]['options'])
        if cline != nline:
            return 'update'
    else:
        return 'add'
    return 'exists'


def rm_auth_key(user, key):
    '''
    Remove an authorized key from the specified user's authorized key file

    CLI Example:

    .. code-block:: bash

        salt '*' pfsense.rm_auth_key <user> <key>
    '''
    if check_key(user, key) == 'add':
        pf_ret = 'Key is not present'
    else:

        client = pfsense.FauxapiLib(debug=True)
        config = client.config_get()
        correct_user = _get_user(user, config)
        authorizedkeys = correct_user['authorizedkeys']
        keys = _decode_keys(authorizedkeys)

        wanted_keys = {}
        to_delete_keys = []
        for k, v in keys.items():
            if k == key:
                to_delete_keys.append(k)
                continue
            else:
                wanted_keys[k] = v

        to_put_keys = _encode_keys(wanted_keys)
        correct_user['authorizedkeys'] = to_put_keys
        pf_ret = client.config_set(config)


    # Now delete all to_delete_keys using normal salt command
    salt_ret = __salt__['ssh.rm_auth_key'](user, key)

    ret = {}
    ret['fauxapi'] = pf_ret
    ret['salt'] = salt_ret
    return ret


def set_auth_key(
        user,
        key,
        enc='ssh-rsa',
        comment='',
        options=None,
        config='.ssh/authorized_keys',
        cache_keys=None):
    '''
    Add a key to the authorized_keys file. The "key" parameter must only be the
    string of text that is the encoded key. If the key begins with "ssh-rsa"
    or ends with user@host, remove those from the key before passing it to this
    function.


    CLI Example:

    .. code-block:: bash

        salt '*' ssh.set_auth_key <user> '<key>'
    '''
    status = check_key(user, key)
    if status != 'add':
        return 'Cannot add key, because it has status {0}'.format(status)

    client = pfsense.FauxapiLib(debug=True)
    config = client.config_get()
    correct_user = _get_user(user, config)
    authorizedkeys = correct_user['authorizedkeys']
    keys = _decode_keys(authorizedkeys)

    keys[key] = {'enc': enc,
                 'comment': comment,
                 'options': options}


    to_put_keys = _encode_keys(keys)
    correct_user['authorizedkeys'] = to_put_keys

    ret = {}

    result = client.config_set(config)
    if 'message' in result:
        ret['fauxapi'] = result['message']
    else:
        return result

    # Now delete all to_delete_keys using normal salt command
    ret['salt'] = __salt__['ssh.set_auth_key'](user=user,
                                               key=key,
                                               enc=enc,
                                               comment=comment,
                                               options=options)
                                               
    return ret


def add_user(name,
             uid=None,
             gid=None,
             groups=None,
             home=None,
             shell=None,
             unique=True,
             system=False,
             fullname='',
             roomnumber='',
             workphone='',
             homephone='',
             createhome=True,
             loginclass=None,
             root=None):
    '''
    Add a user to the minion

    CLI Example:

    .. code-block:: bash

        salt '*' user.add name <uid> <gid> <groups> <home> <shell>
    '''
    client = pfsense.FauxapiLib(debug=True)
    config = client.config_get()
    users = config['system']['user']
    for user in users:
        if user['name'] == name:
            return 'Already present'

    # Call salt command to create
    res = __salt__['user.add'](name, fullname=fullname, gid='nobody', shell='/sbin/nologin')
    if not res:
        return res
    infos = __salt__['user.info'](name)

    # Then update config
    user_data = {
            'uid': infos['uid'],
            'dashboardcolumns': 2,
            'descr': fullname,
            'name': name,
            'disabled': True,
            'authorizedkeys': True,
            'ipsecpsk': True,
            'expires': True,
            'bcrypt-hash': '*',
            'scope': 'user',
            'webguicss': 'pfSense.css'}
    users.append(user_data)
    config['system']['nextuid'] = infos['uid'] + 1

    ret = {'salt': infos}

    result = client.config_set(config)
    if 'message' in result:
        ret['fauxapi'] = result['message']
    else:
        return result


def delete_user(name, remove=False, force=False, root=None):
    '''
    Remove a user from the minion

    CLI Example:

    .. code-block:: bash

        salt '*' user.delete name remove=True force=True
    '''
