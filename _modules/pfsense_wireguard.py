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
import json

# Import Salt libs
import salt.utils.files
import salt.utils.stringutils
import pfsense
from salt.exceptions import (
    CommandExecutionError,
    SaltInvocationError,
)

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)


def list_tunnels():
    """Return dict of tunnels."""
    client = _get_client()
    config = client.config_get()

    ret = {}
    if 'installedpackages' not in config:
        return ret

    config = config['installedpackages']
    if 'wireguard' not in config:
        return ret
    config = config['wireguard']
    if 'tunnels' not in config:
        return ret

    for tunnel in config['tunnels']['item']:
        addresses = tunnel['addresses']
        data_addresses = []
        for address in addresses['row']:
            a = address['address']
            m = address['mask']
            descr = address['descr']
            data_addresses.append({'address': a, 'mask': m, 'descr': descr})

        del tunnel['addresses']
        data = tunnel
        data['addresses'] = data_addresses
        name = tunnel['name']
        ret[name] = data
    return ret


def get_tunnel(name):
    """Return specific tunnel."""
    tunnels = list_tunnels()
    if name not in tunnels:
        return None
    return tunnels[name]


def list_peers():
    """Return dict of tunnels."""
    client = _get_client()
    config = client.config_get()

    ret = {}
    if 'installedpackages' not in config:
        return ret

    config = config['installedpackages']
    if 'wireguard' not in config:
        return ret
    config = config['wireguard']
    if 'peers' not in config:
        return ret

    for peer in config['peers']['item']:
        allowedips = peer['allowedips']
        data_allowed_ips = []
        for ip in allowedips['row']:
            a = ip['address']
            m = ip['mask']
            descr = ip['descr']
            data_allowed_ips.append({'address': a, 'mask': m, 'descr': descr})

        del peer['allowedips']
        data = peer
        data['allowedips'] = data_allowed_ips
        name = peer['descr']
        ret[name] = data
    return ret


def get_peer(name):
    """Return specific tunnel."""
    peers = list_peers()
    if name not in peers:
        return None
    return peers[name]


def add_peer(name,
             tunnel,
             publickey,
             allowip,
             presharedkey=None,
             persistentkeepalive=25,
             enabled=True,
             ):
    """Add a new peer."""
    current_peers = list_peers()
    if name in current_peers:
        return f'Peer {name} already present'
    for peer_name, data in current_peers.items():
        if data['publickey'] == publickey:
            return f'Peer {peeer_name} have the same publickey {publickey}'
        allowed_ips = list(map(lambda x: x['address'], data['allowedips']))
        if allowip in allowed_ips:
            return f'Peer {peer_name} have the same allowip {allowip}'

    if len(publickey) != 44:
        return f"Public key is not of length 44, something is wrong"

    get_tunnel(tunnel)

    client = _get_client()
    config = client.config_get()

    persistentkeepalive = str(persistentkeepalive)
    patch_wireguard_peers = {
        'installedpackages': {
            'wireguard': config['installedpackages']['wireguard']
        },
    }
    new_peer = {
        'descr': name,
        'tun': tunnel,
        'persistentkeepalive': persistentkeepalive,
        'publickey': publickey,
        'allowedips': {'row': [{'address': allowip, 'mask': '32', 'descr': ''}]},
    }
    if presharedkey is not None:
        new_peer['presharedkey'] = presharedkey
    else:
        new_peer['presharedkey'] = ''

    if enabled:
        new_peer['enabled'] = 'yes'
    else:
        new_peer['enabled'] = 'no'
    patch_wireguard_peers['installedpackages']['wireguard']['peers']['item'].append(new_peer)

    response = client.config_patch(patch_wireguard_peers)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add peer', response['message'])

    # Base Settings
    cmd = ['php', '/opt/helpers/regenerate_wireguard.php']

    result = __salt__['cmd.run_all'](cmd,
                                     python_shell=False)

    if result['retcode'] != 0:
        raise CommandExecutionError(result['stdout'])
    else:
        return new_peer
