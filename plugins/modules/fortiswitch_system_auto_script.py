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
module: fortiswitch_system_auto_script
short_description: Configure auto script in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and auto_script category.
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
    - ansible>=2.11
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    system_auto_script:
        description:
            - Configure auto script.
        default: null
        type: dict
        suboptions:
            interval:
                description:
                    - Repeat interval in seconds.
                type: int
            name:
                description:
                    - Auto script name.
                required: true
                type: str
            output_size:
                description:
                    - Number of megabytes to limit script output to (10 - 1024).
                type: int
            repeat:
                description:
                    - Number of times to repeat this script (0 = infinite).
                type: int
            script:
                description:
                    - List of CLI commands to repeat.
                type: str
            start:
                description:
                    - Script starting mode.
                type: str
                choices:
                    - 'manual'
                    - 'auto'
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
  - name: Configure auto script.
    fortiswitch_system_auto_script:
      state: "present"
      system_auto_script:
        interval: "3"
        name: "default_name_4"
        output_size: "5"
        repeat: "6"
        script: "<your_own_value>"
        start: "manual"

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


def filter_system_auto_script_data(json):
    option_list = ['interval', 'name', 'output_size',
                   'repeat', 'script', 'start']

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


def system_auto_script(data, fos):
    state = data['state']
    system_auto_script_data = data['system_auto_script']
    filtered_data = underscore_to_hyphen(filter_system_auto_script_data(system_auto_script_data))

    if state == "present" or state is True:
        return fos.set('system',
                       'auto-script',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system',
                          'auto-script',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):
    fos.do_member_operation('system', 'auto-script')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_auto_script']:
        resp = system_auto_script(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_auto_script'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "output_size": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "output_size",
            "help": "Number of megabytes to limit script output to (10 - 1024,default = 10).",
            "category": "unitary"
        },
        "repeat": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "repeat",
            "help": "Number of times to repeat this script (0 = infinite).",
            "category": "unitary"
        },
        "name": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "name": "name",
            "help": "Auto script name.",
            "category": "unitary"
        },
        "script": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "name": "script",
            "help": "List of CLI commands to repeat.",
            "category": "unitary"
        },
        "interval": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "interval",
            "help": "Repeat interval in seconds.",
            "category": "unitary"
        },
        "start": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "manual",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "auto",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "start",
            "help": "Script starting mode.",
            "category": "unitary"
        }
    },
    "revisions": {
        "v7.2.1": True,
        "v7.2.2": True,
        "v7.2.3": True,
        "v7.2.4": True,
        "v7.2.5": True,
        "v7.4.0": True
    },
    "name": "auto_script",
    "help": "Configure auto script.",
    "mkey": "name",
    "category": "table"
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
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "system_auto_script": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_auto_script"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_auto_script"]['options'][attribute_name]['required'] = True

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_auto_script")
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
