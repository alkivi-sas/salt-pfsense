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


class NatRule:
    """Object that represent a NAT rule in pfSense."""

    # Describe xml key vs object key
    available_keys = {
        'descr': 'descr', 
        'protocol': 'protocol',
        'target': 'target',
        'interface': 'interface',
        'local-port': 'local_port'
    }
    boolean_keys = {
        'disabled': 'disabled',
    }
    special_keys = {
        'source': 'source',
        'destination': 'destination',
    }
    test_keys = {
        'protocol': 'protocol',
        'target': 'target',
        'interface': 'interface',
        'local-port': 'local_port',
        'disabled': 'disabled',
    }

    @staticmethod
    def get_default_source():
        return {'any': {}}

    @staticmethod
    def get_default_destination():
        return {'any': {}}

    def __init__(self,
                 descr,
                 protocol,
                 target,
                 interface,
                 local_port,
                 disabled=False,
                 source={'any': {}},
                 destination={'any': {}},
                 ):
        self.descr = descr
        self.protocol = protocol
        self.target = target
        self.interface = interface
        self.local_port = str(local_port)
        self.disabled = disabled
        self.source = source
        self.destination = destination


    def __eq__(self, other):
        """
        Custom eq method to see if two rules match.

        A rule match if 
        protocol
        target
        interface
        local_port
        source
        destination
        are equals
        """
        logger.debug('test eq')
        logger.debug(self.__dict__)
        logger.debug(other.__dict__)

        for key, self_key in self.test_keys.items():
            my_value = getattr(self, self_key)
            other_value = getattr(other, self_key)
            if my_value != other_value:
                logger.debug('nat rule differs because of {0}'.format(key))
                return False

        # Special keys are dict and must be sub-parsed
        for key, self_key in self.special_keys.items():
            my_value = getattr(self, self_key)
            other_value = getattr(other, self_key)

            # Test Self
            for my_sub_key, my_sub_value in my_value.items():
                if my_sub_key not in other_value:
                    logger.debug('nat rule differs because of {0}:{1}'.format(key, my_sub_key))
                    return False
                other_sub_value = other_value[my_sub_key]
                if other_sub_value != my_sub_value:
                    logger.debug('nat rule differs because of {0}:{1}'.format(key, my_sub_key))
                    return False

            # But also test other
            for other_sub_key, other_sub_value in other_value.items():
                if other_sub_key not in my_value:
                    logger.debug('nat rule differs because of {0}:{1}'.format(key, other_sub_key))
                    return False
                my_sub_value = my_value[other_sub_key]
                if other_sub_value != my_sub_value:
                    logger.debug('nat rule differs because of {0}:{1}'.format(key, other_sub_key))
                    return False

        # OK here
        return True


    @classmethod
    def from_config(cls, config):
        # Generic keys
        params = {}
        for key, self_key in cls.available_keys.items():
            if key in config:
                params[self_key] = config[key]
            else:
                params[self_key] = None
                

        # Boolean
        for key, self_key in cls.boolean_keys.items():
            if key in config:
                params[self_key] = True
            else:
                params[self_key] = False

        # Source and destination
        for key, self_key in cls.special_keys.items():
            if key in config:
                params[self_key] = config[key]

        return cls(**params)

    def to_string(self):
        """Return a string representing the rule."""
        text = 'Interface:{0}'.format(self.interface)
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

        text += ' Nat-To:{0}:{1}'.format(self.target, self.local_port)

        if self.descr:
            text += ' Descr:{0}'.format(self.descr)
        return text


    def to_dict(self):
        """Return a dict representing the rule."""
        object_dict = {}
        for key, self_key in self.available_keys.items():
            object_dict[key] = getattr(self, self_key)
        for key, self_key in self.boolean_keys.items():
            if getattr(self, self_key):
                object_dict[key] = True
        for key, self_key in self.special_keys.items():
            object_dict[key] = getattr(self, self_key)
        return object_dict


def list_rules(out=None):
    '''
    Return the rules found in nat
        [array]
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_nat_rule.list_rules out=string
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
    if 'rule' not in config['nat']:
        return ret

    for data in config['nat']['rule']:
        rule = NatRule.from_config(data)
        if out == 'string':
            ret.append(rule.to_string())
        elif out == 'dict':
            ret.append(rule.to_dict())
        elif out == 'object':
            ret.append(rule)

    return ret


def get_rule_at_index(index):
    '''
    Return the rule
    CLI Example:
    .. code-block:: bash
        salt '*' pfsense_interfaces.get_target interface
    '''
    rules = list_rules()
    if len(rules) <= index:
        raise CommandExecutionError('Wrong index must be in 0 and {0}'.format(len(rules) - 1))

    return rules[index]

def get_rule(descr, protocol, target, interface, local_port, disabled=False, source=None, destination=None):
    """Return the rule dict."""
    if source is None:
        source = NatRule.get_default_source()
    if destination is None:
        destination = NatRule.get_default_destination()

    # Fix integer to string if needed
    if 'port' in source:
        source['port'] = str(source['port'])
    if 'port' in destination:
        destination['port'] = str(destination['port'])

    test_rule = NatRule(descr,
                        protocol,
                        target,
                        interface,
                        local_port,
                        disabled,
                        source,
                        destination)

    present_rules = list_rules(out='object')
    for rule in present_rules:
        if rule == test_rule:
            return rule
    return None


def has_rule(descr, protocol, target, interface, local_port, disabled=False, source=None, destination=None):
    """Return True or False."""
    if source is None:
        source = NatRule.get_default_source()
    if destination is None:
        destination = NatRule.get_default_destination()

    # Fix integer to string if needed
    if 'port' in source:
        source['port'] = str(source['port'])
    if 'port' in destination:
        destination['port'] = str(destination['port'])

    test_rule = NatRule(descr,
                        protocol,
                        target,
                        interface,
                        local_port,
                        disabled,
                        source,
                        destination)

    present_rules = list_rules(out='object')
    if test_rule in present_rules:
        return True
    else:
        return False


def add_rule(descr, protocol, target, interface, local_port, disabled=False, source=None, destination=None, index=0):
    """Return Rule."""
    if source is None:
        source = NatRule.get_default_source()
    if destination is None:
        destination = NatRule.get_default_destination()

    # Fix integer to string if needed
    if 'port' in source:
        source['port'] = str(source['port'])
    if 'port' in destination:
        destination['port'] = str(destination['port'])

    test_rule = NatRule(descr,
                        protocol,
                        target,
                        interface,
                        local_port,
                        disabled,
                        source,
                        destination)

    present_rules = list_rules(out='object')
    if test_rule in present_rules:
        return test_rule.to_dict()

    client = _get_client()
    config = client.config_get()

    logger.warning('init')

    patch_nat_rule = {
        'nat': {
            'rule': config['nat']['rule']
        }
    }
    patch_nat_rule['nat']['rule'].insert(index, test_rule.to_dict())
    response = client.config_patch(patch_nat_rule)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add nat rule', response['message'])

    cmd = ['php', '/opt/helpers/nat_rule.php']

    result = __salt__['cmd.run_all'](cmd,
                                     python_shell=False)

    if result['retcode'] != 0:
        raise CommandExecutionError(result['stdout'])

    return test_rule.to_dict()


def rm_rule(descr, protocol, target, interface, local_port, disabled=False, source=None, destination=None, index=0):
    """Return Rule."""
    if source is None:
        source = NatRule.get_default_source()
    if destination is None:
        destination = NatRule.get_default_destination()

    # Fix integer to string if needed
    if 'port' in source:
        source['port'] = str(source['port'])
    if 'port' in destination:
        destination['port'] = str(destination['port'])

    test_rule = NatRule(descr,
                        protocol,
                        target,
                        interface,
                        local_port,
                        disabled,
                        source,
                        destination)

    present_rules = list_rules(out='object')
    if test_rule not in present_rules:
        return True

    client = _get_client()
    config = client.config_get()

    new_nat_rules = []
    for rule in config['nat']['rule']:
        obj_rule = NatRule.from_config(rule)
        if obj_rule == test_rule:
            continue
        new_nat_rules.append(rule)

    patch_nat_rule = {
        'nat': {
            'rule': new_nat_rules
        }
    }

    response = client.config_patch(patch_nat_rule)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add nat rule', response['message'])


    cmd = ['php', '/opt/helpers/nat_rule.php']

    result = __salt__['cmd.run_all'](cmd,
                                     python_shell=False)

    if result['retcode'] != 0:
        raise CommandExecutionError(result['stdout'])
    return True
