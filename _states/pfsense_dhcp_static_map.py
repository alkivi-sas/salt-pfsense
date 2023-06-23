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

    is_present = __salt__['pfsense_dhcp_static_map.get_static_map'](interface, mac)
    if __opts__['test']:
        if not is_present:
            ret['comment'] = 'Static map is set to be created'
            return ret
        is_ok = __salt__['pfsense_dhcp_static_map.has_static_map'](interface, static_map)
        if is_ok:
            ret['comment'] = 'Static map is already OK'
        else:
            ret['comment'] = 'Static map is set to be updated'
        return ret

    data = __salt__['pfsense_dhcp_static_map.set_static_map'](
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

    if is_present: 
            ret['changes'][mac] = 'Updated'
            ret['comment'] = ('Static map {0} updated'.format(mac))
    else:
        ret['changes'][mac] = 'New'
        ret['comment'] = ('Static map {0} added'.format(mac))
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
