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

"""
                $changes_applied = true;
                $retval = 0;
                $retval |= system_hostname_configure();
                $retval |= system_hosts_generate();
                $retval |= system_resolvconf_generate();
                if (isset($config['dnsmasq']['enable'])) {
                        $retval |= services_dnsmasq_configure();
                } elseif (isset($config['unbound']['enable'])) {
                        $retval |= services_unbound_configure();
                }
                $retval |= system_timezone_configure();
                $retval |= system_ntp_configure();

                if ($olddnsallowoverride != $config['system']['dnsallowoverride']) {
                        $retval |= send_event("service reload dns");
                }

                // Reload the filter - plugins might need to be run.
                $retval |= filter_configure();
"""

def __virtual__():
    if os.path.isfile('/etc/pf.os'):
        return True
    else:
        return False

def _get_client():
    return pfsense.FauxapiLib(debug=True)


def _generate_resolvconf():
    cmd = ['/etc/rc.resolv_conf_generate']
    __salt__['cmd.run_all'](cmd, python_shell=False)


def list_servers():
    """
    Return dns servers with their associated gateway, if present
    """
    client = _get_client()
    config = client.config_get()

    ret = []
    if 'dnsserver' not in config['system']:
        return ret

    servers = []
    for index, server in enumerate(config["system"]["dnsserver"]):
        dns_index = index + 1
        gateway_key = "dns{0}gw".format(dns_index)
        final_data = {
            "dns": server,
            "gateway": None,
        }
        if gateway_key in config["system"]:
            gateway = config["system"][gateway_key]
            if gateway == "":
                gateway = None
            final_data["gateway"] = gateway
        servers.append(final_data)
    return servers

def has_dns(dns):
    servers = list_servers()
    for server in servers:
        if server["dns"] == dns:
            return True
    return False

def get_dns(dns):
    servers = list_servers()
    for server in servers:
        if server["dns"] == dns:
            return server
    return None

def get_dns_gateway(dns):
    server = get_dns(dns)
    if server is None:
        raise CommandExecutionError("No DNS entry with {0}".format(dns))
    return server["gateway"]

def _setup_dns(wanted_dns, wanted_gateways, route_to_delete):
    # First remove rules
    local_gateways = []
    if route_to_delete:
        local_gateways = __salt__["pfsense_gateway.list_gateways"]()
        
    for route in route_to_delete:
        for dns, gateway in route.items():
            real_gateway = list(filter(lambda x: x["name"] == gateway, local_gateways))
            if len(real_gateway) != 1:
                continue
            real_gateway = real_gateway[0]
            if real_gateway["gateway"] == "dynamic":
                continue
            real_gateway = real_gateway["gateway"]

            logging.warning("Deleting DNS {0} via GW {1} using GWIP {2}".format(dns, gateway, real_gateway))
            cmd = "/sbin/route -q delete -host {0} {1}".format(dns, real_gateway)
            result = __salt__["cmd.run"](cmd)
            logging.warning("{0}".format(result))

    client = _get_client()
    config = client.config_get()
    patch_system = {
        'system': {
            'dnsserver': wanted_dns,
        },
    }
    for index, gateway in enumerate(wanted_gateways):
        gw_index = index + 1
        key = "dns{0}gw".format(gw_index)
        if gateway is None:
            gateway = ""
        patch_system["system"][key] = gateway

    response = client.config_patch(patch_system)
    if response['message'] != 'ok':
        raise CommandExecutionError('unable to add peer', response['message'])
    _generate_resolvconf()
    return True


def need_changes(dns, gateway=None, servers=None):
    """Check for need of a DNS changes."""
    if servers is None:
        servers = list_servers()

    changes = {}
    need_to_add = True
    has_changes = False

    for server in servers:
        if server["dns"] == dns:
            need_to_add = False
            logging.warning("{0}".format(server))
            if server["gateway"] != gateway:
                has_changes = True
                changes["gateway"] = gateway

    if need_to_add:
        changes["dns"] = dns

    if not changes:
        return None
    else:
        return changes


def add_dns(dns, gateway=None):
    """Install DNS and associated gateway if need."""
    servers = list_servers()
    dns_to_install = []
    dns_gateway_to_install = []
    dns_route_to_delete = []

    if gateway is not None:
        if not __salt__["pfsense_gateway.has_gateway"](gateway):
            raise CommandExecutionError("You ask for gateway {0} but it does not exist".format(gateway))

    need_to_add = True
    has_changes = False

    for server in servers:
        if server["dns"] == dns:
            need_to_add = False
            logging.warning("{0}".format(server))
            if server["gateway"] != gateway:
                has_changes = True
                dns_gateway_to_install.append(gateway)
                if server["gateway"] is not None:
                    dns_route_to_delete.append({dns: server["gateway"]})
            else:
                dns_gateway_to_install.append(server["gateway"])
        else:
            dns_gateway_to_install.append(server["gateway"])
        dns_to_install.append(server["dns"])

    if need_to_add:
        dns_to_install.append(dns)
        dns_gateway_to_install.append(gateway)

    if not need_to_add and not has_changes:
        return {"changes": None}
    result = _setup_dns(dns_to_install, dns_gateway_to_install, dns_route_to_delete)
    if not result:
        return False

    if need_to_add:
        changes = {"dns": dns}
        if gateway is not None:
            changes["gateway"] = gateway
        return {"changes": changes}
    else:
        return {"changes": {"gateway": gateway}}


def del_dns(dns):
    """Install DNS and associated gateway if need."""
    servers = list_servers()
    dns_to_install = []
    dns_gateway_to_install = []
    dns_route_to_delete = []

    was_present = False

    for server in servers:
        if server["dns"] == dns:
            was_present = True
            if server["gateway"]:
                dns_route_to_delete.append({dns: server["gateway"]})
            continue
        else:
            dns_gateway_to_install.append(server["gateway"])
            dns_to_install.append(server["dns"])

    if not was_present:
        return {"changes": None}

    result = _setup_dns(dns_to_install, dns_gateway_to_install, dns_route_to_delete)
    if not result:
        return False

    return {"changes": {"dns": dns}}


def fix_all_dns(wanted_dns):
    """
    Update a list of DNS.

    wanted_dns : array
    dns as key
    gateway as value
    """
    dns_to_install = []
    dns_gateway_to_install = []
    dns_route_to_delete = []
    dns_to_gateway = {}

    for wanted_data in wanted_dns:
        dns = wanted_data["dns"]
        gateway = wanted_data.get("gateway", None)
        if gateway is not None:
            if not __salt__["pfsense_gateway.has_gateway"](gateway):
                raise CommandExecutionError("You ask for gateway {0} but it does not exist".format(gateway))

        dns_to_install.append(dns)
        dns_gateway_to_install.append(gateway)
        dns_to_gateway[dns] = gateway

    servers = list_servers()
    for server in servers:
        if server["dns"] in dns_to_install:
            if server["gateway"] and server["gateway"] != dns_to_gateway[server["dns"]]:
                dns_route_to_delete.append({dns: server["gateway"]})

    result = _setup_dns(dns_to_install, dns_gateway_to_install, dns_route_to_delete)
    if not result:
        return False

    return {"result": True, "comment": "DNS {0} fixed.".format(dns_to_install)}
