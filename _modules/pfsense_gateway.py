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

logger = logging.getLogger(__name__)

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)


def list_gateways(disable=False, interface=None, ipprotocol='inet'):
    '''
    Return the gateways
    '''
    client = _get_client()
    config = client.config_get()

    if ipprotocol not in ["inet", "inet6"]:
        raise CommandExecutionError("Unknow ipprotocol {0}".format(ipprotocol))

    ret = []
    if "gateways" not in config:
        return ret
    if "gateway_item" not in config["gateways"]:
        return ret

    interfaces = __salt__["pfsense_interface.list_interfaces"]()

    gateways = config["gateways"]["gateway_item"]
    final_result = []
    for gateway in gateways:
        gw_interface = gateway["interface"]
        if gw_interface in interfaces and not interfaces[gw_interface]["enable"]:
                continue
        if interface is not None:
            if gw_interface != interface:
                continue
        if ipprotocol is not None:
            if gateway["ipprotocol"] != ipprotocol:
                continue

        if gateway["gateway"] == "dynamic":
            if gw_interface in interfaces:
                real_if = interfaces[gw_interface]["if"]
                file_to_test = "/tmp/{0}_router".format(real_if)
                if os.path.isfile(file_to_test):
                    with open(file_to_test, 'r') as file:
                        gateway["gateway"] = file.read().strip()

        final_result.append(gateway)
    return final_result

def has_gateway(name):
    gateways = list_gateways()
    for gateway in gateways:
        if gateway["name"] == name:
            return True
    return False
