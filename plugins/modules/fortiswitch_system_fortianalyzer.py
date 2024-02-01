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
module: fortiswitch_system_fortianalyzer
short_description: Setting for FortiAnalyzer in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and fortianalyzer category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v7.0.0
version_added: "1.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)

requirements:
    - ansible>=2.14
options:
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - present
            - absent

    system_fortianalyzer:
        description:
            - Setting for FortiAnalyzer.
        default: null
        type: dict
        suboptions:
            __change_ip:
                description:
                    - Hidden attribute.
                type: int
            address_mode:
                description:
                    - FortiAnalyzer IP addressing mode.
                type: str
                choices:
                    - 'static'
                    - 'auto-discovery'
            conn_timeout:
                description:
                    - FortiAnalyzer connection time-out in seconds (for status and log buffer).
                type: int
            encrypt:
                description:
                    - Whether to send FortiAnalyzer log data in IPsec tunnel.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            fdp_device:
                description:
                    - Serial number of FortiAnalyzer to connect to.
                type: str
            fdp_interface:
                description:
                    - Interface for FortiAnalyzer auto-discovery.
                type: str
            localid:
                description:
                    - Local id for IPsec tunnel to FortiAnalyzer.
                type: str
            mgmt_name:
                description:
                    - Hidden management name of FortiAnalyzer.
                type: str
            psksecret:
                description:
                    - Pre-shared key for IPsec tunnel to FortiAnalyzer.
                type: str
            server:
                description:
                    - IP address of the remote FortiAnalyzer.
                type: str
            status:
                description:
                    - Enable/disable FortiAnalyzer.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
'''

EXAMPLES = '''
- name: Setting for FortiAnalyzer.
  fortinet.fortiswitch.fortiswitch_system_fortianalyzer:
      system_fortianalyzer:
          __change_ip: "3"
          address_mode: "static"
          conn_timeout: "5"
          encrypt: "disable"
          fdp_device: "<your_own_value>"
          fdp_interface: "<your_own_value>"
          localid: "<your_own_value>"
          mgmt_name: "<your_own_value>"
          psksecret: "<your_own_value>"
          server: "192.168.100.40"
          status: "enable"
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
mkey:
  description: Master key (id) used in the last call to FortiSwitch
  returned: success
  type: str
  sample: "id"
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

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import FortiOSHandler
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import schema_to_module_spec
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import check_schema_versioning
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.data_post_processor import remove_invalid_fields


def filter_system_fortianalyzer_data(json):
    option_list = ['__change_ip', 'address_mode', 'conn_timeout',
                   'encrypt', 'fdp_device', 'fdp_interface',
                   'localid', 'mgmt_name', 'psksecret',
                   'server', 'status']

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

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


def system_fortianalyzer(data, fos):
    system_fortianalyzer_data = data['system_fortianalyzer']
    filtered_data = underscore_to_hyphen(filter_system_fortianalyzer_data(system_fortianalyzer_data))

    return fos.set('system',
                   'fortianalyzer',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):
    fos.do_member_operation('system', 'fortianalyzer')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_fortianalyzer']:
        resp = system_fortianalyzer(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_fortianalyzer'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "status",
            "help": "Enable/disable FortiAnalyzer.",
            "category": "unitary"
        },
        "__change_ip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "__change_ip",
            "help": "Hidden attribute.",
            "category": "unitary"
        },
        "encrypt": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "disable"
                },
                {
                    "value": "enable"
                }
            ],
            "name": "encrypt",
            "help": "Whether to send FortiAnalyzer log data in IPsec tunnel.",
            "category": "unitary"
        },
        "localid": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "localid",
            "help": "Local id for IPsec tunnel to FortiAnalyzer.",
            "category": "unitary"
        },
        "fdp_device": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "fdp-device",
            "help": "Serial number of FortiAnalyzer to connect to.",
            "category": "unitary"
        },
        "conn_timeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "conn-timeout",
            "help": "FortiAnalyzer connection time-out in seconds (for status and log buffer).",
            "category": "unitary"
        },
        "psksecret": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "psksecret",
            "help": "Pre-shared key for IPsec tunnel to FortiAnalyzer.",
            "category": "unitary"
        },
        "mgmt_name": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "mgmt-name",
            "help": "Hidden management name of FortiAnalyzer.",
            "category": "unitary"
        },
        "fdp_interface": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "fdp-interface",
            "help": "Interface for FortiAnalyzer auto-discovery.",
            "category": "unitary"
        },
        "server": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "server",
            "help": "IP address of the remote FortiAnalyzer.",
            "category": "unitary"
        },
        "address_mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "static"
                },
                {
                    "value": "auto-discovery"
                }
            ],
            "name": "address-mode",
            "help": "FortiAnalyzer IP addressing mode.",
            "category": "unitary"
        }
    },
    "name": "fortianalyzer",
    "help": "Setting for FortiAnalyzer.",
    "category": "complex"
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    # mkeyname = None
    mkeyname = versioned_schema['mkey'] if 'mkey' in versioned_schema else None
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "system_fortianalyzer": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_fortianalyzer"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_fortianalyzer"]['options'][attribute_name]['required'] = True

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_fortianalyzer")
        is_error, has_changed, result, diff = fortiswitch_system(module.params, fos)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortiSwitch system and your playbook, see more details by specifying option -vvv")

    if not is_error:
        if versions_check_result and versions_check_result['matched'] is False:
            module.exit_json(changed=has_changed, version_check_warning=versions_check_result, meta=result, diff=diff)
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result['matched'] is False:
            module.fail_json(msg="Error in repo", version_check_warning=versions_check_result, meta=result)
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
