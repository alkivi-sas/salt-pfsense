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
    if os.path.isfile('/etc/pf.os'):
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

    if file_exists('/etc/platform'):
        grains['platform'] = file_read('/etc/platform')

    php_command = '''php -r 'require_once("config.inc"); $platform = system_identify_specific_platform(); echo isset($platform["descr"]) ? $platform["descr"] : "non netgate";' '''
    netgate_model = __salt__["cmd.run"](php_command)
    grains['netgate_model'] = netgate_model

    return grains
