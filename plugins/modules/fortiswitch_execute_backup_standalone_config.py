#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortiswitch_execute_backup_standalone_config
short_description: Backup Switch's Standalone Configuration.
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify backup feature and standalone_config category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
version_added: 1.0.0
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
requirements:
    - ansible>=2.11
options:
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    execute_backup_standalone_config:
        description:
            - Backup Switch's Standalone Configuration.
        default: null
        type: dict
        suboptions:
            config:
                description:
                    - Configuration"s Chunked String.
                type: str
'''

RETURN = '''
build:
  description: Build number of the fortiSwitch image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiSwitch
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiSwitch on last operation applied
  returned: always
  type: str
  sample: "200"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FS1D243Z13000122"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
version:
  description: Version of the FortiSwitch
  returned: always
  type: str
  sample: "v7.0.0"
results:
  description: the main output of the execution
  returned: only for successful calls
  type: str
'''

EXAMPLES = '''
- hosts: fortiswitch01
  collections:
    - fortinet.fortiswitch
  connection: httpapi
  vars:
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: no
   ansible_httpapi_port: 443
  tasks:
  - name: Backup Switch's Standalone Configuration.
    execute_backup_standalone_config:
      backup_standalone_config:
        config: "<your_own_value>"
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import FortiOSHandler
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import schema_to_module_spec
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG


def filter_backup_standalone_config_data(config_data):
    option_list = ['config']
    dictionary = {}

    for attribute in option_list:
        if attribute in config_data and config_data[attribute] is not None:
            dictionary[attribute] = config_data[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for i, elem in enumerate(data):
            data[i] = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def backup_standalone_config(data, fos):
    backup_standalone_config_data = data['execute_backup_standalone_config']
    filtered_data = underscore_to_hyphen(filter_backup_standalone_config_data(backup_standalone_config_data))

    return fos.invoke_execute_api(
        'backup',
        'standalone-config',
        data=filtered_data,
    )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_execute_backup_standalone_config(data, fos):
    resp = backup_standalone_config(data, fos)

    return not is_successful_status(resp), \
        is_successful_status(resp), \
        resp


params = {
    "type": "list",
    "children": {
        "config": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        }
    },
    "revisions": {
        "v7.0.3": True,
        "v7.0.2": True,
        "v7.0.1": True,
        "v7.0.0": True,
        "v7.0.6": True,
        "v7.0.5": True,
        "v7.0.4": True
    }
}


def main():
    module_spec = schema_to_module_spec(params)
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "execute_backup_standalone_config": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }

    for attribute_name in module_spec['options']:
        fields["execute_backup_standalone_config"]['options'][attribute_name] = module_spec['options'][attribute_name]

    module = AnsibleModule(
        argument_spec=fields
    )

    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module)
        is_error, has_changed, result = fortiswitch_execute_backup_standalone_config(module.params, fos)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
