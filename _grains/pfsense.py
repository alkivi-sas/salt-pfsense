#!/usr/bin/env python

import os
import re
import salt.utils.files


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

    return grains
