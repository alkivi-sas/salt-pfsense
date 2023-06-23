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
import sys

# Import Salt libs
import salt.utils.files
import salt.utils.stringutils
import pfsense
from salt.exceptions import (
    CommandExecutionError,
)

PY3 = sys.version_info[0] >= 3

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)


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

    decoded = base64.b64decode(raw)
    if PY3:
        decoded = decoded.decode('utf-8')

    keys = decoded.split('\r\n')
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
    if PY3:
        to_put_keys = to_put_keys.encode('utf-8')
    res = base64.b64encode(to_put_keys)
    if PY3:
        res = res.decode('utf-8')
    return res


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


def auth_keys(user,
              config='.ssh/authorized_keys',
              fingerprint_hash_type=None):
    '''
    Return the authorized keys for users

    CLI Example:

    .. code-block:: bash

        salt '*' ssh.auth_keys root
    '''
    client = _get_client()
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


def _validate_keys(key_file, fingerprint_hash_type):
    '''
    Return a dict containing validated keys in the passed file
    '''
    ret = {}
    linere = re.compile(r'^(.*?)\s?((?:ssh\-|ecds)[\w-]+\s.+)$')

    try:
        with salt.utils.files.fopen(key_file, 'r') as _fh:
            for line in _fh:
                # We don't need any whitespace-only containing lines or arbitrary doubled newlines
                line = salt.utils.stringutils.to_unicode(line.strip())
                if line == '':
                    continue
                line += '\n'

                if line.startswith('#'):
                    # Commented Line
                    continue

                # get "{options} key"
                search = re.search(linere, line)
                if not search:
                    # not an auth ssh key, perhaps a blank line
                    continue

                opts = search.group(1)
                comps = search.group(2).split()

                if len(comps) < 2:
                    # Not a valid line
                    continue

                if opts:
                    # It has options, grab them
                    options = opts.split(',')
                else:
                    options = []

                enc = comps[0]
                key = comps[1]
                comment = ' '.join(comps[2:])
                fingerprint = _fingerprint(key, fingerprint_hash_type)
                if fingerprint is None:
                    continue

                ret[key] = {'enc': enc,
                            'comment': comment,
                            'options': options,
                            'fingerprint': fingerprint}
    except (IOError, OSError):
        raise CommandExecutionError(
            'Problem reading ssh key file {0}'.format(key_file)
        )

    return ret


def _fingerprint(public_key, fingerprint_hash_type):
    '''
    Return a public key fingerprint based on its base64-encoded representation
    The fingerprint string is formatted according to RFC 4716 (ch.4), that is,
    in the form "xx:xx:...:xx"
    If the key is invalid (incorrect base64 string), return None
    public_key
        The public key to return the fingerprint for
    fingerprint_hash_type
        The public key fingerprint hash type that the public key fingerprint
        was originally hashed with. This defaults to ``sha256`` if not specified.
        .. versionadded:: 2016.11.4
        .. versionchanged:: 2017.7.0: default changed from ``md5`` to ``sha256``
    '''
    if fingerprint_hash_type:
        hash_type = fingerprint_hash_type.lower()
    else:
        hash_type = 'sha256'

    try:
        hash_func = getattr(hashlib, hash_type)
    except AttributeError:
        raise CommandExecutionError(
            'The fingerprint_hash_type {0} is not supported.'.format(
                hash_type
            )
        )

    try:
        raw_key = base64.b64decode(public_key, validate=True)  # pylint: disable=E1123
    except binascii.Error:
        return None

    ret = hash_func(raw_key).hexdigest()

    chunks = [ret[i:i + 2] for i in range(0, len(ret), 2)]
    return ':'.join(chunks)


def _replace_auth_key(
        user,
        key,
        enc='ssh-rsa',
        comment='',
        options=None,
        config='.ssh/authorized_keys'):
    '''
    Replace an existing key
    '''

    auth_line = _format_auth_line(key, enc, comment, options or [])

    client = _get_client()
    config = client.config_get()
    correct_user = _get_user(user, config)
    authorizedkeys = correct_user['authorizedkeys']
    keys = _decode_keys(authorizedkeys)

    wanted_keys = {}
    for present_key, data in keys.items():
        if present_key == key:
            wanted_keys[key] = {'enc': enc,
                                'comment': comment,
                                'options': options}
        else:
            wanted_keys[present_key] = data

    to_put_keys = _encode_keys(wanted_keys)
    correct_user['authorizedkeys'] = to_put_keys

    result = client.config_set(config)
    if 'message' not in result:
        raise CommandExecutionError('Problem when updating ssh key')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating ssh key')
    return


def check_key(user,
              key,
              enc='ssh-rsa',
              comment='',
              options=None,
              config='.ssh/authorized_keys',
              cache_keys=None,
              fingerprint_hash_type=None):
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


def check_key_file(user,
                   source,
                   config='.ssh/authorized_keys',
                   saltenv='base',
                   fingerprint_hash_type=None):
    '''
    Check a keyfile from a source destination against the local keys and
    return the keys to change
    CLI Example:
    .. code-block:: bash
        salt '*' ssh.check_key_file root salt://ssh/keyfile
    '''
    keyfile = __salt__['cp.cache_file'](source, saltenv)
    if not keyfile:
        return {}

    s_keys = _validate_keys(keyfile, fingerprint_hash_type)
    if not s_keys:
        err = 'No keys detected in {0}. Is file properly ' \
              'formatted?'.format(source)
        log.error(err)
        __context__['ssh_auth.error'] = err
        return {}
    else:
        ret = {}
        for key in s_keys:
            ret[key] = check_key(
                user,
                key,
                s_keys[key]['enc'],
                s_keys[key]['comment'],
                s_keys[key]['options'],
                config=config,
                fingerprint_hash_type=fingerprint_hash_type)
        return ret


def rm_auth_key(user,
                key,
                config='.ssh/authorized_keys',
                fingerprint_hash_type=None):
    '''
    Remove an authorized key from the specified user's authorized key file

    CLI Example:

    .. code-block:: bash

        salt '*' pfsense.rm_auth_key <user> <key>
    '''
    if check_key(user, key) == 'add':
        return 'Key is not present'
    else:

        client = _get_client()
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
        ret = client.config_set(config)
        if ret['message'] != 'ok':
            return 'Key not removed'
        else:
            return 'Key removed'


def set_auth_key(user,
                 key,
                 enc='ssh-rsa',
                 comment='',
                 options=None,
                 config='.ssh/authorized_keys',
                 cache_keys=None,
                 fingerprint_hash_type=None):
    '''
    Add a key to the authorized_keys file. The "key" parameter must only be the
    string of text that is the encoded key. If the key begins with "ssh-rsa"
    or ends with user@host, remove those from the key before passing it to this
    function.
    CLI Example:
    .. code-block:: bash
        salt '*' ssh.set_auth_key <user> '<key>' enc='dsa'
    '''
    if len(key.split()) > 1:
        return 'invalid'

    enc = _refine_enc(enc)

    # A 'valid key' to us pretty much means 'decodable as base64', which is
    # the same filtering done when reading the authorized_keys file. Apply
    # the same check to ensure we don't insert anything that will not
    # subsequently be read)
    key_is_valid = _fingerprint(key, fingerprint_hash_type) is not None
    if not key_is_valid:
        return 'Invalid public key'

    status = check_key(user,
		       key,
                       enc,
                       comment,
                       options,
                       config=config,
                       cache_keys=cache_keys,
                       fingerprint_hash_type=fingerprint_hash_type)

    if status == 'update':
        _replace_auth_key(user, key, enc, comment, options or [], config)
        return 'replace'
    elif status == 'exists':
        return 'no change'

    client = _get_client()
    config = client.config_get()
    correct_user = _get_user(user, config)
    authorizedkeys = correct_user['authorizedkeys']
    keys = _decode_keys(authorizedkeys)

    keys[key] = {'enc': enc,
                 'comment': comment,
                 'options': options}


    to_put_keys = _encode_keys(keys)
    correct_user['authorizedkeys'] = to_put_keys

    result = client.config_set(config)
    if 'message' not in result:
        raise CommandExecutionError('Problem when updating ssh key')
    elif result['message'] != 'ok':
        logger.warning(result)
        raise CommandExecutionError('Problem when updating ssh key')
    return 'new'


def set_auth_key_from_file(user,
                           source,
                           config='.ssh/authorized_keys',
                           saltenv='base',
                           fingerprint_hash_type=None):
    '''
    Add a key to the authorized_keys file, using a file as the source.
    CLI Example:
    .. code-block:: bash
        salt '*' ssh.set_auth_key_from_file <user> salt://ssh_keys/<user>.id_rsa.pub
    '''
    # TODO: add support for pulling keys from other file sources as well
    lfile = __salt__['cp.cache_file'](source, saltenv)
    if not os.path.isfile(lfile):
        raise CommandExecutionError(
            'Failed to pull key file from salt file server'
        )

    s_keys = _validate_keys(lfile, fingerprint_hash_type)
    if not s_keys:
        err = (
            'No keys detected in {0}. Is file properly formatted?'.format(
                source
            )
        )
        log.error(err)
        __context__['ssh_auth.error'] = err
        return 'fail'
    else:
        rval = ''
        for key in s_keys:
            rval += set_auth_key(
                user,
                key,
                enc=s_keys[key]['enc'],
                comment=s_keys[key]['comment'],
                options=s_keys[key]['options'],
                config=config,
                cache_keys=list(s_keys.keys()),
                fingerprint_hash_type=fingerprint_hash_type
            )
        # Due to the ability for a single file to have multiple keys, it's
        # possible for a single call to this function to have both "replace"
        # and "new" as possible valid returns. I ordered the following as I
        # thought best.
        if 'fail' in rval:
            return 'fail'
        elif 'replace' in rval:
            return 'replace'
        elif 'new' in rval:
            return 'new'
        else:
            return 'no change'


def rm_auth_key_from_file(user,
                          source,
                          config='.ssh/authorized_keys',
                          saltenv='base',
                          fingerprint_hash_type=None):
    '''
    Remove an authorized key from the specified user's authorized key file,
    using a file as source
    CLI Example:
    .. code-block:: bash
        salt '*' ssh.rm_auth_key_from_file <user> salt://ssh_keys/<user>.id_rsa.pub
    '''
    lfile = __salt__['cp.cache_file'](source, saltenv)
    if not os.path.isfile(lfile):
        raise CommandExecutionError(
            'Failed to pull key file from salt file server'
        )

    s_keys = _validate_keys(lfile, fingerprint_hash_type)
    if not s_keys:
        err = (
            'No keys detected in {0}. Is file properly formatted?'.format(
                source
            )
        )
        log.error(err)
        __context__['ssh_auth.error'] = err
        return 'fail'
    else:
        rval = ''
        for key in s_keys:
            rval += rm_auth_key(
                user,
                key,
                config=config,
                fingerprint_hash_type=fingerprint_hash_type
            )
        # Due to the ability for a single file to have multiple keys, it's
        # possible for a single call to this function to have both "replace"
        # and "new" as possible valid returns. I ordered the following as I
        # thought best.
        if 'Key not removed' in rval:
            return 'Key not removed'
        elif 'Key removed' in rval:
            return 'Key removed'
        else:
            return 'Key not present'
