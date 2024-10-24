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
module: fortiswitch_log_fortianalyzer_override_setting
short_description: Setting for FortiAnalyzer in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify log_fortianalyzer feature and override_setting category.
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
    - ansible>=2.15
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

    log_fortianalyzer_override_setting:
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
            buffer_max_send:
                description:
                    - Maximum log transmission rate for buffered logs.
                type: int
            conn_timeout:
                description:
                    - FortiAnalyzer connection time-out in seconds (for status and log buffer).
                type: int
            enc_algorithm:
                description:
                    - Whether to send FortiAnalyzer log data with SSL encryption.
                type: str
                choices:
                    - 'default'
                    - 'high'
                    - 'low'
                    - 'disable'
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
            hmac_algorithm:
                description:
                    - FortiAnalyzer IPsec tunnel HMAC algorithm.
                type: str
                choices:
                    - 'sha256'
                    - 'sha1'
            ips_archive:
                description:
                    - Whether to enable IPS packet archive.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            localid:
                description:
                    - Local id for IPsec tunnel to FortiAnalyzer.
                type: str
            max_buffer_size:
                description:
                    - Maximum buffer size, in MBytes, 0--1024, 0=disabled.
                type: int
            mgmt_name:
                description:
                    - Hidden management name of FortiAnalyzer.
                type: str
            override:
                description:
                    - Override FortiAnalyzer settings or use the global settings.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            psksecret:
                description:
                    - Pre-shared key for IPsec tunnel to FortiAnalyzer.
                type: str
            server:
                description:
                    - IP address of the remote FortiAnalyzer.
                type: str
            source_ip:
                description:
                    - Source IP address of the FortiAnalyzer.
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
  fortinet.fortiswitch.fortiswitch_log_fortianalyzer_override_setting:
      log_fortianalyzer_override_setting:
          __change_ip: "3"
          address_mode: "static"
          buffer_max_send: "5"
          conn_timeout: "6"
          enc_algorithm: "default"
          encrypt: "disable"
          fdp_device: "<your_own_value>"
          fdp_interface: "<your_own_value> (source system.interface.name)"
          hmac_algorithm: "sha256"
          ips_archive: "enable"
          localid: "<your_own_value>"
          max_buffer_size: "14"
          mgmt_name: "<your_own_value>"
          override: "enable"
          psksecret: "<your_own_value>"
          server: "192.168.100.40"
          source_ip: "<your_own_value>"
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
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import is_same_comparison
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import serialize
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import find_current_values


def filter_log_fortianalyzer_override_setting_data(json):
    option_list = ['__change_ip', 'address_mode', 'buffer_max_send',
                   'conn_timeout', 'enc_algorithm', 'encrypt',
                   'fdp_device', 'fdp_interface', 'hmac_algorithm',
                   'ips_archive', 'localid', 'max_buffer_size',
                   'mgmt_name', 'override', 'psksecret',
                   'server', 'source_ip', 'status']

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


def log_fortianalyzer_override_setting(data, fos, check_mode=False):
    state = data.get('state', None)

    log_fortianalyzer_override_setting_data = data['log_fortianalyzer_override_setting']

    filtered_data = filter_log_fortianalyzer_override_setting_data(log_fortianalyzer_override_setting_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('log.fortianalyzer', 'override-setting', filtered_data)
        current_data = fos.get('log.fortianalyzer', 'override-setting', mkey=mkey)
        is_existed = current_data and current_data.get('http_status') == 200 \
            and isinstance(current_data.get('results'), list) \
            and len(current_data['results']) > 0

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == 'present' or state is True or state is None:
            mkeyname = fos.get_mkeyname(None, None)
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)

            # handle global modules'
            if mkeyname is None and state is None:
                is_same = is_same_comparison(
                    serialize(current_data['results']), serialize(copied_filtered_data))

                current_values = find_current_values(copied_filtered_data, current_data['results'])

                return False, not is_same, filtered_data, {"before": current_values, "after": copied_filtered_data}

            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data['results'][0]), serialize(copied_filtered_data))

                current_values = find_current_values(copied_filtered_data, current_data['results'][0])

                return False, not is_same, filtered_data, {"before": current_values, "after": copied_filtered_data}

            # record does not exist
            return False, True, filtered_data, diff

        if state == 'absent':
            if mkey is None:
                return False, False, filtered_data, {"before": current_data['results'][0], "after": ''}

            if is_existed:
                return False, True, filtered_data, {"before": current_data['results'][0], "after": ''}
            return False, False, filtered_data, {}

        return True, False, {'reason: ': 'Must provide state parameter'}, {}

    return fos.set('log.fortianalyzer',
                   'override-setting',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_log_fortianalyzer(data, fos, check_mode):
    fos.do_member_operation('log.fortianalyzer', 'override-setting')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['log_fortianalyzer_override_setting']:
        resp = log_fortianalyzer_override_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('log_fortianalyzer_override_setting'))
    if check_mode:
        return resp
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
        "enc_algorithm": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "default"
                },
                {
                    "value": "high"
                },
                {
                    "value": "low"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "enc-algorithm",
            "help": "Whether to send FortiAnalyzer log data with SSL encryption.",
            "category": "unitary"
        },
        "hmac_algorithm": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "sha256"
                },
                {
                    "value": "sha1"
                }
            ],
            "name": "hmac-algorithm",
            "help": "FortiAnalyzer IPsec tunnel HMAC algorithm.",
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
        "ips_archive": {
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
            "name": "ips-archive",
            "help": "Whether to enable IPS packet archive.",
            "category": "unitary"
        },
        "source_ip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "source-ip",
            "help": "Source IP address of the FortiAnalyzer.",
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
        "max_buffer_size": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "max-buffer-size",
            "help": "Maximum buffer size,in MBytes,0--1024,0=disabled.",
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
        "override": {
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
            "name": "override",
            "help": "Override FortiAnalyzer settings or use the global settings.",
            "category": "unitary"
        },
        "buffer_max_send": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "buffer-max-send",
            "help": "Maximum log transmission rate for buffered logs.",
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
    "name": "override-setting",
    "help": "Setting for FortiAnalyzer.",
    "category": "complex"
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = versioned_schema['mkey'] if 'mkey' in versioned_schema else None
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "log_fortianalyzer_override_setting": {
            "required": False, "type": "dict", "default": None,
            "no_log": True,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["log_fortianalyzer_override_setting"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["log_fortianalyzer_override_setting"]['options'][attribute_name]['required'] = True

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=True)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_custom_option('enable_log', module.params['enable_log'])
        else:
            connection.set_custom_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "log_fortianalyzer_override_setting")
        is_error, has_changed, result, diff = fortiswitch_log_fortianalyzer(module.params, fos, module.check_mode)
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
