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
module: fortiswitch_system_ptp_profile
short_description: PTP policy configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system_ptp feature and profile category.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    system_ptp_profile:
        description:
            - PTP policy configuration.
        default: null
        type: dict
        suboptions:
            announce_interval:
                description:
                    - Announce interval.
                type: str
                choices:
                    - '0.25sec'
                    - '0.5sec'
                    - '1sec'
                    - '2sec'
                    - '4sec'
            announce_timeout:
                description:
                    - PTP Announce timeout (2-10)
                type: int
            description:
                description:
                    - Description.
                type: str
            domain:
                description:
                    - PTP domain (0-255)
                type: int
            min_delay_req_interval:
                description:
                    - Min Delay Request interval.
                type: str
                choices:
                    - '0.25sec'
                    - '0.5sec'
                    - '1sec'
                    - '2sec'
                    - '4sec'
            mode:
                description:
                    - Select PTP mode.
                type: str
                choices:
                    - 'transparent-e2e'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            pdelay_req_interval:
                description:
                    - PDelay Request interval.
                type: str
                choices:
                    - '0.25sec'
                    - '0.5sec'
                    - '1sec'
                    - '2sec'
                    - '4sec'
            priority1:
                description:
                    - PTP priority1 (0-255)
                type: int
            priority2:
                description:
                    - PTP priority2 (0-255)
                type: int
            ptp_profile:
                description:
                    - Select PTP profile.
                type: str
                choices:
                    - 'C37.238-2017'
                    - 'default'
            sync_interval:
                description:
                    - Sync interval.
                type: str
                choices:
                    - '0.25sec'
                    - '0.5sec'
                    - '1sec'
                    - '2sec'
                    - '4sec'
            transport:
                description:
                    - Select PTP transport.
                type: str
                choices:
                    - 'l2-mcast'
'''

EXAMPLES = '''
- name: PTP policy configuration.
  fortinet.fortiswitch.fortiswitch_system_ptp_profile:
      state: "present"
      system_ptp_profile:
          announce_interval: "0.25sec"
          announce_timeout: "4"
          description: "<your_own_value>"
          domain: "6"
          min_delay_req_interval: "0.25sec"
          mode: "transparent-e2e"
          name: "default_name_9"
          pdelay_req_interval: "0.25sec"
          priority1: "11"
          priority2: "12"
          ptp_profile: "C37.238-2017"
          sync_interval: "0.25sec"
          transport: "l2-mcast"
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


def filter_system_ptp_profile_data(json):
    option_list = ['announce_interval', 'announce_timeout', 'description',
                   'domain', 'min_delay_req_interval', 'mode',
                   'name', 'pdelay_req_interval', 'priority1',
                   'priority2', 'ptp_profile', 'sync_interval',
                   'transport']

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


def system_ptp_profile(data, fos):
    state = data['state']
    system_ptp_profile_data = data['system_ptp_profile']
    filtered_data = underscore_to_hyphen(filter_system_ptp_profile_data(system_ptp_profile_data))

    if state == "present" or state is True:
        return fos.set('system.ptp',
                       'profile',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system.ptp',
                          'profile',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system_ptp(data, fos):
    fos.do_member_operation('system.ptp', 'profile')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_ptp_profile']:
        resp = system_ptp_profile(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_ptp_profile'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "domain": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "domain",
            "help": "PTP domain (0-255)",
            "category": "unitary"
        },
        "name": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "name",
            "help": "Profile name.",
            "category": "unitary"
        },
        "pdelay_req_interval": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "0.25sec"
                },
                {
                    "value": "0.5sec"
                },
                {
                    "value": "1sec"
                },
                {
                    "value": "2sec"
                },
                {
                    "value": "4sec"
                }
            ],
            "name": "pdelay-req-interval",
            "help": "PDelay Request interval.",
            "category": "unitary"
        },
        "mode": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "transparent-e2e"
                }
            ],
            "name": "mode",
            "help": "Select PTP mode.",
            "category": "unitary"
        },
        "ptp_profile": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "C37.238-2017"
                },
                {
                    "value": "default",
                    "v_range": []
                }
            ],
            "name": "ptp-profile",
            "help": "Select PTP profile.",
            "category": "unitary"
        },
        "transport": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "l2-mcast"
                }
            ],
            "name": "transport",
            "help": "Select PTP transport.",
            "category": "unitary"
        },
        "description": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "description",
            "help": "Description.",
            "category": "unitary"
        },
        "priority1": {
            "v_range": [],
            "type": "integer",
            "name": "priority1",
            "help": "PTP priority1 (0-255)",
            "category": "unitary"
        },
        "announce_interval": {
            "v_range": [],
            "type": "string",
            "options": [
                {
                    "value": "0.25sec"
                },
                {
                    "value": "0.5sec"
                },
                {
                    "value": "1sec"
                },
                {
                    "value": "2sec"
                },
                {
                    "value": "4sec"
                }
            ],
            "name": "announce-interval",
            "help": "Announce interval.",
            "category": "unitary"
        },
        "min_delay_req_interval": {
            "v_range": [],
            "type": "string",
            "options": [
                {
                    "value": "0.25sec"
                },
                {
                    "value": "0.5sec"
                },
                {
                    "value": "1sec"
                },
                {
                    "value": "2sec"
                },
                {
                    "value": "4sec"
                }
            ],
            "name": "min-delay-req-interval",
            "help": "Min Delay Request interval.",
            "category": "unitary"
        },
        "sync_interval": {
            "v_range": [],
            "type": "string",
            "options": [
                {
                    "value": "0.25sec"
                },
                {
                    "value": "0.5sec"
                },
                {
                    "value": "1sec"
                },
                {
                    "value": "2sec"
                },
                {
                    "value": "4sec"
                }
            ],
            "name": "sync-interval",
            "help": "Sync interval.",
            "category": "unitary"
        },
        "priority2": {
            "v_range": [],
            "type": "integer",
            "name": "priority2",
            "help": "PTP priority2 (0-255)",
            "category": "unitary"
        },
        "announce_timeout": {
            "v_range": [],
            "type": "integer",
            "name": "announce-timeout",
            "help": "PTP Announce timeout (2-10)",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.4.0",
            ""
        ]
    ],
    "name": "profile",
    "help": "PTP policy configuration.",
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
        "system_ptp_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_ptp_profile"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_ptp_profile"]['options'][attribute_name]['required'] = True

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
            connection.set_custom_option('enable_log', module.params['enable_log'])
        else:
            connection.set_custom_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_ptp_profile")
        is_error, has_changed, result, diff = fortiswitch_system_ptp(module.params, fos)
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
