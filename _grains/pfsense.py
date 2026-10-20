#!/usr/bin/env python

import os
import re
import salt.modules.cmdmod
import salt.utils.files


__salt__ = {
    "cmd.run": salt.modules.cmdmod._run_quiet,
    "cmd.run_all": salt.modules.cmdmod._run_all_quiet,
}


def __virtual__():
    if os.path.isfile("/etc/inc/pfsense-utils.inc"):
        return True
    else:
        return False

def pfsense_grains():
    grains = {}

    def file_exists(path):
        return os.path.isfile(os.path.expanduser(path))

    def file_read(path):
        data = ''
        with salt.utils.files.fopen(path, 'r') as file_obj:
            data = file_obj.read()
        return re.sub(r'\W+', '', data)

    if file_exists('/etc/version'):
        grains['version'] = file_read('/etc/version')
        # Raw base and edition: '26.07-RELEASE' -> 26.07 / Plus, '2.8.1-RELEASE' -> 2.8.1 / CE
        with salt.utils.files.fopen('/etc/version', 'r') as file_obj:
            match = re.match(r'^(\d+(?:\.\d+)+)', file_obj.read().strip())
        if match:
            grains['pfsense_base'] = match.group(1)
            grains['pfsense_edition'] = 'CE' if int(match.group(1).split('.')[0]) < 20 else 'Plus'

    # Installed pfSense-pkg-RESTAPI version ('' when absent), e.g. 2.10_2
    result = __salt__["cmd.run_all"](['pkg', 'query', '%v', 'pfSense-pkg-RESTAPI'], python_shell=False)
    grains['pfrest_version'] = result['stdout'].strip() if result['retcode'] == 0 else ''

    if file_exists('/etc/platform'):
        grains['platform'] = file_read('/etc/platform')

    try:
        php_command = '''php -r 'require_once("config.inc"); $platform = system_identify_specific_platform(); echo isset($platform["descr"]) ? $platform["descr"] : "non netgate";' '''
        netgate_model = __salt__["cmd.run"](php_command)
        grains['netgate_model'] = netgate_model
    except Exception:
        pass

    return grains
