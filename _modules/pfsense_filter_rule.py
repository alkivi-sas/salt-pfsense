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

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)


def format_source_and_destination(data):
    if isinstance(data, dict):
        if 'port' in data:
            data['port'] = str(data['port'])
    return dict(data)


def format_protocol(data):
    if data == 'any':
        return None
    return data


def format_bool_to_yes(data):
    if data:
        return 'yes'
    return None


def format_interface(data):
    if data == '':
        return None
    return data


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
            'default': '',
            'type': 'str',
            'formater': format_interface
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
            'formater': format_protocol
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
            'formater': format_source_and_destination 
        },
        'destination': {
            'default': {'any': ''},
            'formater': format_source_and_destination 
        },
        'floating': {
            'default': False,
            'type': 'bool',
            'formater': format_bool_to_yes
        },
        'quick': {
            'default': False,
            'type': 'bool',
            'formater': format_bool_to_yes
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
        and floating match
        and interface match
        """
        if self.descr != other.descr:
            return False
        if self.floating != other.floating:
            return False
        if self.floating:
            return True
        if self.interface != other.interface:
            return False
        return True

    def is_valid(self):
        # Basic from keys
        for key, configuration in self.keys.items():
            type = configuration.get('type', None)
            valid = configuration.get('valid', None)

            # No key, continue
            if not hasattr(self, key):
                continue

            # Key value from type
            value = None
            if type in [None, 'str']:
                value = getattr(self, key)
            elif type == 'bool':
                if getattr(self, key):
                    value = ''
            elif type == 'int':
                value = str(getattr(self, key))
            else:
                raise CommandExecutionError('Should not come here type is {0}'.format(type))

        # Protocol and ports
        if self.protocol not in ['tcp', 'udp', 'tcp/udp']:
            for key in ['source', 'destination']:
                if 'port' in getattr(self, key):
                    return "You can't use ports on protocol other than tcp, udp or tcp/udp"

        # Quick
        if self.quick:
            if not self.floating:
                return 'If quick is enabled, you also need floating'

        # If not floating then interface
        if not self.floating:
            if not hasattr(self, 'interface') or not self.interface:
                return 'Interface is missing'

        return True


    def match_index(self, other):
        """Check if a rule has the same interface or floating."""
        # Not the same floating : False
        if self.floating != other.floating:
            return False
        # Floating is present -> this is the index
        if self.floating:
            return True

        # Interface
        if self.interface != other.interface:
            return False

        return True

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
                if key in config:
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
            formater = configuration.get('formater', None)
            valid = configuration.get('valid', None)

            # No key, continue
            if not hasattr(self, key):
                continue

            # Key value from type
            value = None
            if type in [None, 'str']:
                value = getattr(self, key)
                if formater is not None:
                    value = formater(value)
            elif type == 'bool':
                value = getattr(self, key)
                if formater is not None:
                    value = formater(value)
                elif value:
                    value = ''
                else:
                    value = None
            elif type == 'int':
                value = str(getattr(self, key))
                if formater is not None:
                    value = formater(value)
            else:
                raise CommandExecutionError('Should not come here dzadazdazdza')

            if value is None:
                continue
            object_dict[key] = value

        # Tracker is compute automatically
        if 'tracker' not in object_dict:
            object_dict['tracker'] = str(int(time.time()))

        return object_dict


def enable_logging_for_all_rules():
    client = _get_client()
    config = client.config_get()

    actual_rules = []
    if 'rule' in config['filter']:
        actual_rules = config['filter']['rule']

    ret = []
    for rule in actual_rules:
        if 'log' not in rule:
            data_rule = FilterRule.from_config(rule)
            ret.append('Log enabled for {0}'.format(data_rule.to_string()))
            rule['log'] = ''


    patch_filter_rule = {
        'filter': {
            'rule': actual_rules,
        }
    }

    response = client.config_patch(patch_filter_rule)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add filter rule', response['message'])

    response = client.send_event('filter reload')
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to filter reload', response['message'])

    return ret


def list_rules(interface=None, floating=None, out=None):
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
            if rule.interface != interface:
                continue

        if floating is not None:
            if rule.floating != floating:
                continue

        if out == 'string':
            ret.append(rule.to_string())
        elif out == 'dict':
            ret.append(rule.to_dict())
        elif out == 'object':
            ret.append(rule)

    return ret


def get_rule(descr=None, interface=None, floating=None, tracker=None):
    """Return the rule dict."""
    # Fix integer to string if needed
    if descr is None and tracker is None:
        raise CommandExecutionError('You must pass either descr and tracker')

    if interface is None and floating is None:
        raise CommandExecutionError('You must pass either interface or floating')

    present_rules = list_rules(out='object', interface=interface, floating=floating)
    for rule in present_rules:
        ok_rule = True
        if descr is not None:
            if rule.descr != descr:
                ok_rule = False
        if tracker is not None:
            if rule.tracker != int(tracker):
                ok_rule = False
        if ok_rule:
            return rule
    return None


def has_rule(descr, interface=None, floating=None):
    """Return True or False."""
    # Fix integer to string if needed
    rule = get_rule(descr, interface, floating)
    if rule is None:
        return False
    else:
        return True


def add_rule(index=0, **kwargs):
    """Return Rule."""
    # Fix integer to string if needed
    test_rule = FilterRule(**kwargs)

    existing_rule = get_rule(test_rule.descr, test_rule.interface, test_rule.floating)
    if existing_rule is not None:
        return existing_rule.to_dict()

    is_rule_valid = test_rule.is_valid()
    if is_rule_valid is not True:
        raise CommandExecutionError('Rule is not valid because "{0}"'.format(is_rule_valid))

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
    base_index = _get_index_for_rule(test_rule)
    final_index = base_index + index

    patch_filter_rule['filter']['rule'].insert(final_index, test_rule.to_dict())
    response = client.config_patch(patch_filter_rule)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add filter rule', response['message'])

    response = client.send_event('filter reload')
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to filter reload', response['message'])

    return test_rule.to_dict()


def _get_index_for_rule(wanted_rule):
    """Return index of the first rule matching interface."""
    index = 0
    present_rules = list_rules(out='object')
    for rule in present_rules:
        if rule.match_index(wanted_rule):
            return index
        index += 1
    return index


def rm_rule(descr, interface=None, floating=None):
    """Return Rule."""
    if interface is None and floating is None:
        raise CommandExecutionError('You must pass either interface or floating')

    rule_to_delete = get_rule(descr, interface=interface, floating=floating)
    if rule_to_delete is None:
        return True

    client = _get_client()
    config = client.config_get()

    new_filter_rules = []
    for rule in config['filter']['rule']:
        obj_rule = FilterRule.from_config(rule)
        if obj_rule == rule_to_delete:
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

def patch_rule(descr=None, tracker=None, interface=None, floating=None, patch={}):
    """
    Patch a rule using kwargs : WIP
    """

    if descr is None and tracker is None:
        raise CommandExecutionError('You must pass either descr and tracker')

    if interface is None and floating is None:
        raise CommandExecutionError('You must pass either interface or floating')

    rule_to_patch = get_rule(descr=descr, interface=interface, floating=floating, tracker=tracker)
    if rule_to_patch is None:
        raise CommandExecutionError('Unable to find a rule with description {0} and tracker {1}'.format(descr, tracker))

    has_changes = False
    allowed_keys = ["source", "descr"]
    for key, configuration in rule_to_patch.keys.items():
        if key not in allowed_keys:
            continue
        if key in patch:
            current_value = getattr(rule_to_patch, key)
            wanted_value = patch[key]
            if current_value != wanted_value:
                has_changes = True
                break

    if not has_changes:
        logging.debug("No changes")
        return True

    client = _get_client()
    config = client.config_get()

    new_filter_rules = []
    for rule in config['filter']['rule']:
        obj_rule = FilterRule.from_config(rule)
        if obj_rule == rule_to_patch:
            new_rule_dict = obj_rule.to_dict()
            for key, configuration in rule_to_patch.keys.items():
                if key not in allowed_keys:
                    continue
                if key in patch:
                    current_value = getattr(rule_to_patch, key)
                    wanted_value = patch[key]
                    if current_value != wanted_value:
                        new_rule_dict[key] = wanted_value
            new_filter_rules.append(new_rule_dict)
        else:
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
