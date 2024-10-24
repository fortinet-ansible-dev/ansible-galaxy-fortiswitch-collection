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
module: fortiswitch_system_accprofile
short_description: Configure system administrative access group in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and accprofile category.
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
    system_accprofile:
        description:
            - Configure system administrative access group.
        default: null
        type: dict
        suboptions:
            admingrp:
                description:
                    - Administrative access permission.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            alias_commands:
                description:
                    - Alias commands (or groups of commands) that can be used by this profile.
                type: list
                elements: dict
                suboptions:
                    command_name:
                        description:
                            - Alias command or group name.
                        type: str
            exec_alias_grp:
                description:
                    - Permission to execute alias commands.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            loggrp:
                description:
                    - Logging access permission.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'w'
                    - 'r'
                    - 'rw'
            mntgrp:
                description:
                    - Critical system maintenance access permission.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            netgrp:
                description:
                    - Network access permission.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            pktmongrp:
                description:
                    - Packet and flow capture functionality.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            routegrp:
                description:
                    - Routing access permission.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            swcoregrp:
                description:
                    - Switch core access permission.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            swmonguardgrp:
                description:
                    - Switch monitor and guard feature permission.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            sysgrp:
                description:
                    - System access permission.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            utilgrp:
                description:
                    - Utilities access permission.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
'''

EXAMPLES = '''
- name: Configure system administrative access group.
  fortinet.fortiswitch.fortiswitch_system_accprofile:
      state: "present"
      system_accprofile:
          admingrp: "none"
          alias_commands:
              -
                  command_name: "<your_own_value> (source system.alias.command.name system.alias.group.name)"
          exec_alias_grp: "none"
          loggrp: "none"
          mntgrp: "none"
          name: "default_name_9"
          netgrp: "none"
          pktmongrp: "none"
          routegrp: "none"
          swcoregrp: "none"
          swmonguardgrp: "none"
          sysgrp: "none"
          utilgrp: "none"
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


def filter_system_accprofile_data(json):
    option_list = ['admingrp', 'alias_commands', 'exec_alias_grp',
                   'loggrp', 'mntgrp', 'name',
                   'netgrp', 'pktmongrp', 'routegrp',
                   'swcoregrp', 'swmonguardgrp', 'sysgrp',
                   'utilgrp']

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


def system_accprofile(data, fos, check_mode=False):
    state = data.get('state', None)

    system_accprofile_data = data['system_accprofile']

    filtered_data = filter_system_accprofile_data(system_accprofile_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('system', 'accprofile', filtered_data)
        current_data = fos.get('system', 'accprofile', mkey=mkey)
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

    if state == "present" or state is True:
        return fos.set('system',
                       'accprofile',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system',
                          'accprofile',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos, check_mode):
    fos.do_member_operation('system', 'accprofile')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_accprofile']:
        resp = system_accprofile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_accprofile'))
    if check_mode:
        return resp
    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "exec_alias_grp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                }
            ],
            "name": "exec-alias-grp",
            "help": "Permission to execute alias commands.",
            "category": "unitary"
        },
        "name": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "name",
            "help": "Profile name.",
            "category": "unitary"
        },
        "sysgrp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                }
            ],
            "name": "sysgrp",
            "help": "System access permission.",
            "category": "unitary"
        },
        "loggrp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                },
                {
                    "value": "w"
                },
                {
                    "value": "r"
                },
                {
                    "value": "rw"
                }
            ],
            "name": "loggrp",
            "help": "Logging access permission.",
            "category": "unitary"
        },
        "netgrp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                }
            ],
            "name": "netgrp",
            "help": "Network access permission.",
            "category": "unitary"
        },
        "admingrp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                }
            ],
            "name": "admingrp",
            "help": "Administrative access permission.",
            "category": "unitary"
        },
        "routegrp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                }
            ],
            "name": "routegrp",
            "help": "Routing access permission.",
            "category": "unitary"
        },
        "alias_commands": {
            "type": "list",
            "elements": "dict",
            "children": {
                "command_name": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "command-name",
                    "help": "Alias command or group name.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "alias-commands",
            "help": "Alias commands (or groups of commands) that can be used by this profile.",
            "mkey": "command-name",
            "category": "table"
        },
        "swmonguardgrp": {
            "v_range": [
                [
                    "v7.2.1",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                }
            ],
            "name": "swmonguardgrp",
            "help": "Switch monitor and guard feature permission.",
            "category": "unitary"
        },
        "mntgrp": {
            "v_range": [
                [
                    "v7.2.1",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                }
            ],
            "name": "mntgrp",
            "help": "Critical system maintenance access permission.",
            "category": "unitary"
        },
        "pktmongrp": {
            "v_range": [
                [
                    "v7.2.1",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                }
            ],
            "name": "pktmongrp",
            "help": "Packet and flow capture functionality.",
            "category": "unitary"
        },
        "swcoregrp": {
            "v_range": [
                [
                    "v7.2.1",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                }
            ],
            "name": "swcoregrp",
            "help": "Switch core access permission.",
            "category": "unitary"
        },
        "utilgrp": {
            "v_range": [
                [
                    "v7.2.1",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "read"
                },
                {
                    "value": "read-write"
                }
            ],
            "name": "utilgrp",
            "help": "Utilities access permission.",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "name": "accprofile",
    "help": "Configure system administrative access group.",
    "mkey": "name",
    "category": "table"
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
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "system_accprofile": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_accprofile"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_accprofile"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_accprofile")
        is_error, has_changed, result, diff = fortiswitch_system(module.params, fos, module.check_mode)
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
