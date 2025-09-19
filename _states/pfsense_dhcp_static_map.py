# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, unicode_literals, print_function
import re
import sys


def present(
        name,
        interface,
        mac,
        ipaddr,
        hostname,
        cid=None,
        descr=None,
        filename=None,
        rootpath=None,
        defaultleasetime=None,
        maxleasetime=None,
        gateway=None,
        domain=None,
        domainsearchlist=None,
        ddnsdomain=None,
        ddnsdomainprimary=None,
        ddnsdomainkeyname=None,
        ddnsdomainkey=None,
        tftp=None,
        ldap=None):
    '''
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    # Build desired data according to default/known keys used by the execution module
    desired = {
        'mac': mac,
        'ipaddr': ipaddr,
        'hostname': hostname,
    }
    optional_keys = [
        'cid',
        'descr',
        'filename',
        'rootpath',
        'defaultleasetime',
        'maxleasetime',
        'gateway',
        'domain',
        'domainsearchlist',
        'ddnsdomain',
        'ddnsdomainprimary',
        'ddnsdomainkeyname',
        'ddnsdomainkey',
        'tftp',
        'ldap',
    ]
    provided_kwargs = {
        'cid': cid,
        'descr': descr,
        'filename': filename,
        'rootpath': rootpath,
        'defaultleasetime': defaultleasetime,
        'maxleasetime': maxleasetime,
        'gateway': gateway,
        'domain': domain,
        'domainsearchlist': domainsearchlist,
        'ddnsdomain': ddnsdomain,
        'ddnsdomainprimary': ddnsdomainprimary,
        'ddnsdomainkeyname': ddnsdomainkeyname,
        'ddnsdomainkey': ddnsdomainkey,
        'tftp': tftp,
        'ldap': ldap,
    }
    for key in optional_keys:
        if provided_kwargs.get(key) is not None:
            desired[key] = provided_kwargs[key]

    current = __salt__['pfsense_dhcp_static_map.get_static_map'](interface, mac)

    if current is None:
        if __opts__['test']:
            ret['comment'] = 'Static map is set to be created'
            ret['changes'][mac] = {'old': None, 'new': desired}
            return ret

        __salt__['pfsense_dhcp_static_map.set_static_map'](
            interface,
            mac,
            ipaddr,
            hostname,
            cid=cid,
            descr=descr,
            filename=filename,
            rootpath=rootpath,
            defaultleasetime=defaultleasetime,
            maxleasetime=maxleasetime,
            gateway=gateway,
            domain=domain,
            domainsearchlist=domainsearchlist,
            ddnsdomain=ddnsdomain,
            ddnsdomainprimary=ddnsdomainprimary,
            ddnsdomainkeyname=ddnsdomainkeyname,
            ddnsdomainkey=ddnsdomainkey,
            tftp=tftp,
            ldap=ldap)
        ret['changes'][mac] = 'New'
        ret['comment'] = ('Static map {0} added'.format(mac))
        return ret

    # Compare only the desired keys; ignore other keys present on the device
    diffs = {}
    for key, desired_value in desired.items():
        current_value = current.get(key)
        if current_value != desired_value:
            diffs[key] = {'old': current_value, 'new': desired_value}

    if not diffs:
        ret['comment'] = 'Static map is already OK'
        return ret

    if __opts__['test']:
        ret['comment'] = 'Static map is set to be updated'
        ret['changes'][mac] = diffs
        return ret

    __salt__['pfsense_dhcp_static_map.set_static_map'](
        interface,
        mac,
        ipaddr,
        hostname,
        cid=cid,
        descr=descr,
        filename=filename,
        rootpath=rootpath,
        defaultleasetime=defaultleasetime,
        maxleasetime=maxleasetime,
        gateway=gateway,
        domain=domain,
        domainsearchlist=domainsearchlist,
        ddnsdomain=ddnsdomain,
        ddnsdomainprimary=ddnsdomainprimary,
        ddnsdomainkeyname=ddnsdomainkeyname,
        ddnsdomainkey=ddnsdomainkey,
        tftp=tftp,
        ldap=ldap)

    ret['changes'][mac] = diffs
    ret['comment'] = ('Static map {0} updated'.format(mac))
    return ret


def absent(name, interface, mac):
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    is_present = __salt__['pfsense_dhcp_static_map.get_static_map'](interface, mac)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Static map is not present'
        else:
            ret['comment'] = 'Static map set to be removed'
        return ret

    data = __salt__['pfsense_dhcp_static_map.rm_static_map'](interface, mac)

    if is_present: 
        ret['changes'][mac] = 'Removed'
        ret['comment'] = ('Static map {0} removed'.format(mac))
    else:
        ret['comment'] = ('Static map {0} already removed'.format(mac))
    return ret


def apply(name):
    '''
    Apply pending pfSense DHCP static map configuration changes in one commit.
    Intended to be used with watch/watch_in requisites.
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    if __opts__['test']:
        ret['comment'] = 'Pending configuration would be applied'
        return ret

    changed = __salt__['pfsense_dhcp_static_map.apply']()
    if changed:
        ret['changes']['config'] = 'applied'
        ret['comment'] = 'Pending DHCP static map configuration applied'
    else:
        ret['comment'] = 'No pending DHCP static map changes to apply'
    return ret
