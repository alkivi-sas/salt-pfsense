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

    # Describe xml key vs object key
    available_keys = {
        'max-src-states': 'max_src_states',
        'tagged': 'tagged',
        'statetimeout': 'statetimeout',
        'descr': 'descr', 
        'statetype': 'statetype',
        'max': '_max',
        'max-src-nodes': 'max_src_nodes',
        'max-src-conn': 'max_src_conn',
        'tag': 'tag',
        'tracker': 'tracker',
        'type': '_type',
        'interface': 'interface',
        'ipprotocol': 'ipprotocol',
        'os': 'os',
        'id': '_id',
        'protocol': 'protocol',
    }
    boolean_keys = {
        'disabled': 'disabled',
    }
    special_keys = {
        'source': 'source',
        'destination': 'destination',
    }
    test_keys = {
        'max-src-states': 'max_src_states',
        'tagged': 'tagged',
        'statetimeout': 'statetimeout',
        'descr': 'descr', 
        'statetype': 'statetype',
        'max': '_max',
        'max-src-nodes': 'max_src_nodes',
        'max-src-conn': 'max_src_conn',
        'tag': 'tag',
        'type': '_type',
        'interface': 'interface',
        'ipprotocol': 'ipprotocol',
        'os': 'os',
        'id': '_id',
        'protocol': 'protocol',
    }

    @staticmethod
    def get_default_source():
        return {'any': ''}

    @staticmethod
    def get_default_destination():
        return {'any': ''}

    @staticmethod
    def get_default_statetype():
        return 'keep state'

    @staticmethod
    def get_defaut_ipprotocol():
        return 'inet'

    @staticmethod
    def get_default_tracker():
        return str(int(time.time()))

    def __init__(self,
                 descr,
                 protocol,
                 interface,
                 _type,
                 max_src_states='',
                 tagged='',
                 statetimeout='',
                 _max='',
                 max_src_nodes='',
                 max_src_conn='',
                 tag='',
                 os='',
                 _id='',
                 disabled=False,
                 tracker=None,
                 ipprotocol=None,
                 statetype=None,
                 source=None,
                 destination=None):

        if ipprotocol is None:
            ipprotocol = self.get_defaut_ipprotocol()
        if statetype is None:
            statetype = self.get_default_statetype()
        if source is None:
            source = self.get_default_source()
        if destination is None:
            destination = self.get_default_destination()
        if tracker is None:
            tracker = self.get_default_tracker()
        self.descr = descr
        self.protocol = protocol
        self.interface = interface
        self.max_src_states = max_src_states
        self.tagged = tagged
        self.statetimeout = statetimeout
        self._max = _max
        self.max_src_nodes = max_src_nodes
        self.max_src_conn = max_src_conn
        self.tag = tag
        self.tracker = tracker
        self._type = _type
        self.os = os
        self._id = _id
        self.disabled = disabled
        self.ipprotocol = ipprotocol
        self.statetype = statetype
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
                logger.debug('filter rule differs because of {0}'.format(key))
                return False

        # Special keys are dict and must be sub-parsed
        for key, self_key in self.special_keys.items():
            my_value = getattr(self, self_key)
            other_value = getattr(other, self_key)

            # Test Self
            for my_sub_key, my_sub_value in my_value.items():
                if my_sub_key not in other_value:
                    logger.debug('filter rule differs because of {0}:{1}'.format(key, my_sub_key))
                    return False
                other_sub_value = other_value[my_sub_key]
                if other_sub_value != my_sub_value:
                    logger.debug('filter rule differs because of {0}:{1}'.format(key, my_sub_key))
                    return False

            # But also test other
            for other_sub_key, other_sub_value in other_value.items():
                if other_sub_key not in my_value:
                    logger.debug('filter rule differs because of {0}:{1}'.format(key, other_sub_key))
                    return False
                my_sub_value = my_value[other_sub_key]
                if other_sub_value != my_sub_value:
                    logger.debug('filter rule differs because of {0}:{1}'.format(key, other_sub_key))
                    return False

        # OK here
        logger.debug('rule match')
        return True


    @classmethod
    def from_config(cls, config):
        # Generic keys
        params = {}
        for key, self_key in cls.available_keys.items():
            if key in config:
                if config[key]:
                    params[self_key] = config[key]
                else:
                    params[self_key] = ''
            else:
                params[self_key] = ''
                

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
        for key, self_key in self.available_keys.items():
            object_dict[key] = getattr(self, self_key)
        for key, self_key in self.boolean_keys.items():
            if getattr(self, self_key):
                object_dict[key] = True
        for key, self_key in self.special_keys.items():
            object_dict[key] = getattr(self, self_key)
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
            if rule.interface != interface:
                continue

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

def get_rule(descr,
             protocol,
             interface,
             _type,
             max_src_states='',
             tagged='',
             statetimeout='',
             _max='',
             max_src_nodes='',
             max_src_conn='',
             tag='',
             os='',
             _id='',
             disabled=False,
             tracker=None,
             ipprotocol=None,
             statetype=None,
             source=None,
             destination=None):
    """Return the rule dict."""
    # Fix integer to string if needed
    source = _clean_source(source)
    destination = _clean_destination(destination)

    test_rule = FilterRule(descr,
                           protocol,
                           interface,
                           _type,
                           max_src_states,
                           tagged,
                           statetimeout,
                           _max,
                           max_src_nodes,
                           max_src_conn,
                           tag,
                           os,
                           _id,
                           disabled,
                           tracker,
                           ipprotocol,
                           statetype,
                           source,
                           destination)

    present_rules = list_rules(out='object')
    for rule in present_rules:
        if rule == test_rule:
            return rule.to_dict()
    return None


def has_rule(descr,
             protocol,
             interface,
             _type,
             max_src_states='',
             tagged='',
             statetimeout='',
             _max='',
             max_src_nodes='',
             max_src_conn='',
             tag='',
             os='',
             _id='',
             disabled=False,
             tracker=None,
             ipprotocol=None,
             statetype=None,
             source=None,
             destination=None):
    """Return True or False."""
    # Fix integer to string if needed
    source = _clean_source(source)
    destination = _clean_destination(destination)

    test_rule = FilterRule(descr,
                           protocol,
                           interface,
                           _type,
                           max_src_states,
                           tagged,
                           statetimeout,
                           _max,
                           max_src_nodes,
                           max_src_conn,
                           tag,
                           os,
                           _id,
                           disabled,
                           tracker,
                           ipprotocol,
                           statetype,
                           source,
                           destination)

    present_rules = list_rules(out='object')
    if test_rule in present_rules:
        return True
    else:
        return False


def add_rule(descr,
             protocol,
             interface,
             _type,
             max_src_states='',
             tagged='',
             statetimeout='',
             _max='',
             max_src_nodes='',
             max_src_conn='',
             tag='',
             os='',
             _id='',
             disabled=False,
             tracker=None,
             ipprotocol=None,
             statetype=None,
             source=None,
             destination=None,
             index=0):
    """Return Rule."""
    # Fix integer to string if needed
    source = _clean_source(source)
    destination = _clean_destination(destination)

    test_rule = FilterRule(descr,
                           protocol,
                           interface,
                           _type,
                           max_src_states,
                           tagged,
                           statetimeout,
                           _max,
                           max_src_nodes,
                           max_src_conn,
                           tag,
                           os,
                           _id,
                           disabled,
                           tracker,
                           ipprotocol,
                           statetype,
                           source,
                           destination)

    present_rules = list_rules(out='object')
    if test_rule in present_rules:
        return test_rule.to_dict()

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
    base_index = _get_index_for_interface(interface)
    final_index = base_index + index

    #logger.debug('rule at index {0}'.format(final_index))
    #logger.debug(patch_filter_rule['filter']['rule'][final_index])
    #logger.debug('rule to add')
    #logger.debug(test_rule.to_dict())

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


def _clean_source(source):
    if isinstance(source, dict):
        if 'port' in source:
            source['port'] = str(source['port'])
    return source


def _clean_destination(destination):
    if isinstance(destination, dict):
        if 'port' in destination:
            destination['port'] = str(destination['port'])
    return destination


def rm_rule(descr, protocol, target, interface, local_port, disabled=False, source=None, destination=None, index=0):
    """Return Rule."""
    # Fix integer to string if needed
    source = _clean_source(source)
    destination = _clean_destination(destination)

    test_rule = FilterRule(descr,
                           protocol,
                           interface,
                           _type,
                           max_src_states,
                           tagged,
                           statetimeout,
                           _max,
                           max_src_nodes,
                           max_src_conn,
                           tag,
                           os,
                           _id,
                           disabled,
                           tracker,
                           ipprotocol,
                           statetype,
                           source,
                           destination)

    present_rules = list_rules(out='object')
    if test_rule not in present_rules:
        return True

    client = _get_client()
    config = client.config_get()

    new_filter_rules = []
    for rule in config['filter']['rule']:
        obj_rule = FilterRule.from_config(rule)
        if obj_rule == test_rule:
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
