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
module: fortiswitch_system_alertemail
short_description: Alert e-mail mail server configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and alertemail category.
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

    system_alertemail:
        description:
            - Alert e-mail mail server configuration.
        default: null
        type: dict
        suboptions:
            authenticate:
                description:
                    - Enable/disable authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            password:
                description:
                    - Set SMTP server user password for authentication.
                type: str
            port:
                description:
                    - Set SMTP server port.
                type: int
            server:
                description:
                    - Set SMTP server IP address or hostname.
                type: str
            source_ip:
                description:
                    - Set SMTP server source ip.
                type: str
            username:
                description:
                    - Set SMTP server user name for authentication.
                type: str
'''

EXAMPLES = '''
- name: Alert e-mail mail server configuration.
  fortinet.fortiswitch.fortiswitch_system_alertemail:
      system_alertemail:
          authenticate: "enable"
          password: "<your_own_value>"
          port: "5"
          server: "192.168.100.40"
          source_ip: "<your_own_value>"
          username: "<your_own_value>"
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


def filter_system_alertemail_data(json):
    option_list = ['authenticate', 'password', 'port',
                   'server', 'source_ip', 'username']

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


def system_alertemail(data, fos):
    system_alertemail_data = data['system_alertemail']
    filtered_data = underscore_to_hyphen(filter_system_alertemail_data(system_alertemail_data))

    return fos.set('system',
                   'alertemail',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):
    fos.do_member_operation('system', 'alertemail')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_alertemail']:
        resp = system_alertemail(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_alertemail'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "v_range": [
        [
            "v7.0.0",
            "v7.0.6"
        ]
    ],
    "type": "dict",
    "children": {
        "username": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "string",
            "name": "username",
            "help": "Set SMTP server user name for authentication.",
            "category": "unitary"
        },
        "authenticate": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
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
            "name": "authenticate",
            "help": "Enable/disable authentication.",
            "category": "unitary"
        },
        "source_ip": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "string",
            "name": "source-ip",
            "help": "Set SMTP server source ip.",
            "category": "unitary"
        },
        "server": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "string",
            "name": "server",
            "help": "Set SMTP server IP address or hostname.",
            "category": "unitary"
        },
        "password": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "string",
            "name": "password",
            "help": "Set SMTP server user password for authentication.",
            "category": "unitary"
        },
        "port": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "integer",
            "name": "port",
            "help": "Set SMTP server port.",
            "category": "unitary"
        }
    },
    "name": "alertemail",
    "help": "Alert e-mail mail server configuration.",
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
        "system_alertemail": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_alertemail"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_alertemail"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_alertemail")
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
