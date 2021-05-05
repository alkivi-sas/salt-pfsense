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
import time

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


class FilterRule:
    """Object that represent a Filter rule in pfSense."""

    keys = {
        'max-src-states': {
            'default': '',
            'type': 'str',
        },
        'tagged': {
            'default': '',
            'type': 'str',
        },
        'statetimeout': {
            'default': '',
            'type': 'str',
        },
        'descr': {
            'required': True,
            'type': 'str',
        },
        'statetype': {
            'default': 'keep state',
            'valid': ['keep state', 'sloppy state', 'synproxy state', 'none'],
        },
        'max': {
            'default': '',
            'type': 'str',
        },
        'max-src-nodes': {
            'default': '',
            'type': 'str',
        },
        'max-src-conn': {
            'default': '',
            'type': 'str',
        },
        'tag': {
            'default': '',
            'type': 'str',
        },
        'type': {
            'default': 'pass',
            'valid': ['pass', 'block', 'match', 'reject'],
        },
        'interface': {
            'required': True,
            'type': 'str',
        },
        'ipprotocol': {
            'default': 'inet', 
            'valid': ['inet', 'inet46', 'inet6'],
        },
        'os': {
            'default': '',
            'type': 'str',
        },
        'id': {
            'default': '',
            'type': 'str',
        },
        'protocol': {
            'default': 'any',
            'valid': ['any', 'tcp', 'udp', 'tcp/udp', 'icmp', 'igmp', 'ospf', 'esp', 'ah', 'gre', 'pim', 'sctp', 'pfsync', 'carp'],
        },
        'disabled': {
            'default': False,
            'type': 'bool',
        },
        'log': {
            'default': False,
            'type': 'bool',
        },
        'source': {
            'default': {'any': ''},
        },
        'destination': {
            'default': {'any': ''},
        },
        'floating': {
            'default': False,
            'type': 'bool',
        },
        'quick': {
            'default': False,
            'type': 'bool',
        },
        'direction': {
            'required': False,
            'valid': ['any', 'in', 'out'],
        },
        'tracker': {
            'required': False,
            'type': 'int'
        }
    }


    @staticmethod
    def clean_source(source):
        if isinstance(source, dict):
            if 'port' in source:
                source['port'] = str(source['port'])
        return dict(source)

    @staticmethod
    def clean_destination(destination):
        if isinstance(destination, dict):
            if 'port' in destination:
                destination['port'] = str(destination['port'])
        return dict(destination)

    def __init__(self, **kwargs):
        for key, configuration in self.keys.items():
            required = configuration.get('required', False)
            value = configuration.get('default', None)
            if key in kwargs:
                value = kwargs[key]
            elif required:
                raise CommandExecutionError('Key {0} is mandatory'.format(key))

            if value is not None:
                setattr(self, key, value)
                
    def __eq__(self, other):
        """
        Custom eq method to see if two rules match.

        A rule match if descr match
        """
        return other.descr == self.descr

    @classmethod
    def from_config(cls, config):
        # Generic keys
        params = {}
        for key, configuration in cls.keys.items():
            type = configuration.get('type', None)
            if type in [None, 'str']:
                if key in config:
                    if config[key]:
                        params[key] = config[key]
                    else:
                        params[key] = ''
                else:
                    params[key] = ''
            elif type == 'bool':
                if key in config:
                    params[key] = True
                else:
                    params[key] = False
            elif type == 'int':
                params[key] = int(config[key])
            else:
                raise CommandExecutionError('Should not come here adazdaza')
        return cls(**params)

    def to_string(self):
        """Return a string representing the rule."""
        text = 'Interface:{0}'.format(self.interface)
        text += ' IPProtocol:{0}'.format(self.ipprotocol)
        text += ' Protocol:{0}'.format(self.protocol)

        # Source
        if 'any' in self.source:
            source = '*'
        elif 'address' in self.source:
            source = self.source['address']
        elif 'network' in self.source:
            source = self.source['network']

        if 'port' in self.source:
            source += ':{0}'.format(self.source['port'])
        text += ' From:{0}'.format(source)

        # Destination
        if 'any' in self.destination:
            destination = '*'
        elif 'address' in self.destination:
            destination = self.destination['address']
        elif 'network' in self.destination:
            destination = self.destination['network']

        if 'port' in self.destination:
            destination += ':{0}'.format(self.destination['port'])
        text += ' To:{0}'.format(destination)

        if self.descr:
            text += ' Descr:{0}'.format(self.descr)
        return text


    def to_dict(self):
        """Return a dict representing the rule."""
        object_dict = {}
        for key, configuration in self.keys.items():
            type = configuration.get('type', None)
            if not hasattr(self, key):
                continue

            value = None
            if type in [None, 'str']:
                value = getattr(self, key)
            elif type == 'bool':
                if getattr(self, key):
                    value = ''
            elif type == 'int':
                value = str(getattr(self, key))
            else:
                raise CommandExecutionError('Should not come here dzadazdazdza')

            if key == 'protocol' and value == 'any':
                value = None

            if value is None:
                continue

            if key == 'source':
                value = self.clean_source(value)
            elif key == 'destination':
                value = self.clean_destination(value)
            object_dict[key] = value

        if 'tracker' not in object_dict:
            object_dict['tracker'] = str(int(time.time()))
        return object_dict


def list_rules(interface=None, out=None):
    '''
    Return the rules found in filter
        [array]
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_nat_rule.list_rules out=string interface=wan
        salt '*' pfsense_nat_rule.list_rules out=dict
    '''
    client = _get_client()
    config = client.config_get()

    if out is None:
        out = 'dict'

    ok_out = ['string', 'dict', 'object']
    if out not in ok_out:
        raise CommandExecutionError('out must be in {0}'.format(ok_out))

    ret = []
    if 'rule' not in config['filter']:
        return ret

    for data in config['filter']['rule']:
        rule = FilterRule.from_config(data)

        if interface is not None:
            if interface == 'floating':
                if not rule.floating:
                    continue
            elif rule.interface != interface:
                continue

        if out == 'string':
            ret.append(rule.to_string())
        elif out == 'dict':
            ret.append(rule.to_dict())
        elif out == 'object':
            ret.append(rule)

    return ret


def get_rule_at_index(index, interface):
    '''
    Return the rule
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_interfaces.get_target interface
    '''
    rules = list_rules(interface=interface)
    if len(rules) <= index:
        raise CommandExecutionError('Wrong index must be in 0 and {0}'.format(len(rules) - 1))

    return rules[index]

def get_rule(descr,
             interface):
    """Return the rule dict."""
    # Fix integer to string if needed
    present_rules = list_rules(out='object', interface=interface)
    for rule in present_rules:
        if rule.descr == descr:
            return rule.to_dict()
    return None


def has_rule(descr,
             interface):
    """Return True or False."""
    # Fix integer to string if needed
    rule = get_rule(descr, interface)
    if rule is None:
        return False
    else:
        return True


def add_rule(index=0, **kwargs):
    """Return Rule."""
    # Fix integer to string if needed
    test_rule = FilterRule(**kwargs)

    present_rules = list_rules(out='object', interface=test_rule.interface)
    existing_rule = get_rule(test_rule.descr, test_rule.interface)
    if existing_rule is not None:
        return existing_rule.to_dict()

    client = _get_client()
    config = client.config_get()

    actual_rules = []
    if 'rule' in config['filter']:
        actual_rules = config['filter']['rule']

    patch_filter_rule = {
        'filter': {
            'rule': actual_rules,
        }
    }

    # Now found base index for interface
    base_index = _get_index_for_interface(test_rule.interface)
    final_index = base_index + index

    logger.debug('rule at index {0}'.format(final_index))
    logger.debug(patch_filter_rule['filter']['rule'][final_index])
    logger.debug('rule to add')
    logger.debug(test_rule.to_dict())

    patch_filter_rule['filter']['rule'].insert(final_index, test_rule.to_dict())
    response = client.config_patch(patch_filter_rule)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add filter rule', response['message'])

    response = client.send_event('filter reload')
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to filter reload', response['message'])

    return test_rule.to_dict()


def _get_index_for_interface(interface):
    """Return index of the first rule matching interface."""
    index = 0
    present_rules = list_rules(out='object')
    for rule in present_rules:
        if rule.interface == interface:
            return index
        index += 1
    return index


def rm_rule(descr, interface):
    """Return Rule."""
    rule = get_rule(descr, interface)
    if rule is None:
        return True

    client = _get_client()
    config = client.config_get()

    new_filter_rules = []
    for rule in config['filter']['rule']:
        obj_rule = FilterRule.from_config(rule)
        if obj_rule.descr == descr and obj_rule.interface == interface:
            continue
        new_filter_rules.append(rule)

    patch_filter_rule = {
        'filter': {
            'rule': new_filter_rules
        }
    }

    response = client.config_patch(patch_filter_rule)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add filter rule', response['message'])

    response = client.send_event('filter reload')
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to filter reload', response['message'])

    return True
