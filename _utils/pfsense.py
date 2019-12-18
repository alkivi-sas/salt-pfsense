# -*- coding: utf-8 -*-
"""
Util for FauxapiLib
"""
from __future__ import absolute_import

# Import Python libs
import os
import re
import json
import base64
import logging
import requests
import datetime
import hashlib

import salt.modules.cmdmod
import salt.utils.files
from salt.exceptions import CommandExecutionError

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

FAUXAPI_HOST = '127.0.0.1'

log = logging.getLogger(__name__)

# Load the __salt__ dunder if not already loaded (when called from utils-module)
__salt__ = {
    'cmd.run': salt.modules.cmdmod._run_quiet,
}

class FauxapiLibException(Exception):
    pass

class FauxapiLib:

    host = None
    proto = None
    debug = None
    apikey = None
    apisecret = None
    use_snakeoil_https = None

    def __init__(self, host=None, apikey=None, apisecret=None, 
                 use_verified_https=False, debug=False):

        if not host:
            host = FAUXAPI_HOST
        if not apikey:
            apikey = self._get_apikey()
		
        if not apisecret:
            apisecret = self._get_apisecret(apikey)

        self.proto = 'https'
        self.base_url = 'fauxapi/v1'
        self.host = host
        self.apikey = apikey
        self.apisecret = apisecret
        self.use_verified_https = use_verified_https
        self.debug = debug
        if not self.use_verified_https:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


    def _get_apikey(self):
        '''
        Parse /etc/fauxapi/credentials.ini

        Return the first line that match [PFFA 12 to 40 characters]
        '''
        credentials = '/etc/fauxapi/credentials.ini'
        if not os.path.isfile(credentials):
            raise CommandExecutionError('You must create {0} first'.format(credentials))

        re_pattern = re.compile('^\[(PFFA[A-Za-z0-9]{8,36})\]$')
        with salt.utils.files.fopen(credentials, 'r') as fp_:
            for line in fp_.readlines():
                m = re_pattern.search(line)
                if m:
                    return m.group(1)
        raise CommandExecutionError('Unable to extract PFFA key from {0}'.format(credentials))

    def _get_apisecret(self, key):
        '''Parse /etc/fauxapi/credentials.ini.
        
        Return the first line with secret avec key has been found
        '''
        credentials = '/etc/fauxapi/credentials.ini'
        if not os.path.isfile(credentials):
            raise CommandExecutionError('You must create {0} first'.format(credentials))

        re_pattern = re.compile('^secret\s=\s(.*)$')
        find_key = False
        with salt.utils.files.fopen(credentials, 'r') as fp_:
            for line in fp_.readlines():
                if not find_key:
                    if key in line:
                        find_key = True
                else:
                    m = re_pattern.search(line)
                    if m:
                        return m.group(1)
        if not find_key:
            raise CommandExecutionError('Unable to find key {1} in {0}'.format(key, credentials))
        else:
            raise CommandExecutionError('Unable to extract secret associated to key {1} in {0}'.format(key, credentials))

    def config_get(self, section=None):
        config = self._api_request('GET', 'config_get')
        if section is None:
            return config['data']['config']
        elif section in config['data']['config']:
            return config['data']['config'][section]
        raise FauxapiLibException('unable to complete config_get request, section is unknown', section)

    def config_set(self, config_user, section=None):
        if section is None:
            config = config_user
        else:
            config = self.config_get(section=None)
            config[section] = config_user
        res = self._api_request('POST', 'config_set', data=json.dumps(config))

        # Fix chmod for file
        __salt__['cmd.run']('chmod 644 /cf/conf/config.xml')

        return res

    def config_patch(self, config):
        res = self._api_request('POST', 'config_patch', data=json.dumps(config))

        # Fix chmod for file
        __salt__['cmd.run']('chmod 644 /cf/conf/config.xml')

        return res

    def config_reload(self):
        return self._api_request('GET', 'config_reload')

    def config_backup(self):
        return self._api_request('GET', 'config_backup')

    def config_backup_list(self):
        return self._api_request('GET', 'config_backup_list')

    def config_restore(self, config_file):
        return self._api_request('GET', 'config_restore', params={'config_file': config_file})

    def send_event(self, command):
        return self._api_request('POST', 'send_event', data=json.dumps([command]))

    def system_reboot(self):
        return self._api_request('GET', 'system_reboot')

    def system_stats(self):
        return self._api_request('GET', 'system_stats')

    def gateway_status(self):
        return self._api_request('GET', 'gateway_status')

    def rule_get(self, rule_number=None):
        return self._api_request('GET', 'rule_get', params={'rule_number': rule_number})

    def alias_update_urltables(self, table=None):
        if table is not None:
            return self._api_request('GET', 'alias_update_urltables', params={'table': table})
        return self._api_request('GET', 'alias_update_urltables')

    def function_call(self, data):
        return self._api_request('POST', 'function_call', data=json.dumps(data))

    def _api_request(self, method, action, params=None, data=None):
        if params is None:
            params = {}

        if self.debug:
            params['__debug'] = 'true'

        url = '{proto}://{host}/{base_url}/?action={action}&{params}'.format(
            proto=self.proto, host=self.host, base_url=self.base_url, action=action, params=urlencode(params))

        if method.upper() == 'GET':
            res = requests.get(url,
                headers={'fauxapi-auth': self._generate_auth()},
                verify=self.use_verified_https
            )
        elif method.upper() == 'POST':
            res = requests.post(url,
                headers={'fauxapi-auth': self._generate_auth()},
                verify=self.use_verified_https,
                data=data
            )
        else:
            raise FauxapiLibException('request method not supported!', method)

        if res.status_code == 404:
            raise FauxapiLibException('Unable to find FauxAPI on target host, is it installed?')
        elif res.status_code != 200:
            raise FauxapiLibException('Unable to complete {}() request'.format(action), json.loads(res.text))

        return self._json_parse(res.text)

    def _generate_auth(self):
        # auth = apikey:timestamp:nonce:HASH(apisecret:timestamp:nonce)
        nonce = base64.b64encode(os.urandom(40)).decode('utf-8').replace('=', '').replace('/', '').replace('+', '')[0:8]
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dZ%H%M%S')
        hash = hashlib.sha256('{}{}{}'.format(self.apisecret, timestamp, nonce).encode('utf-8')).hexdigest()
        return '{}:{}:{}:{}'.format(self.apikey, timestamp, nonce, hash)

    def _json_parse(self, data):
	try:
	    return json.loads(data)
	except json.JSONDecodeError:
	    pass
	raise PfsenseFauxapiException('Unable to parse response data!', data)

