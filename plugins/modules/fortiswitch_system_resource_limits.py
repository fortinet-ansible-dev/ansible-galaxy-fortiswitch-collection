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
module: fortiswitch_system_resource_limits
short_description: Resource limits configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and resource_limits category.
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

    system_resource_limits:
        description:
            - Resource limits configuration.
        default: null
        type: dict
        suboptions:
            custom_service:
                description:
                    - Maximum number of firewall custom services.
                type: int
            dialup_tunnel:
                description:
                    - Maximum number of dial-up tunnels.
                type: int
            firewall_address:
                description:
                    - Maximum number of firewall addresses.
                type: int
            firewall_addrgrp:
                description:
                    - Maximum number of firewall address groups.
                type: int
            firewall_policy:
                description:
                    - Maximum number of firewall policies.
                type: int
            ipsec_phase1:
                description:
                    - Maximum number of vpn ipsec phase1 tunnels.
                type: int
            ipsec_phase2:
                description:
                    - Maximum number of vpn ipsec phase2 tunnels.
                type: int
            log_disk_quota:
                description:
                    - Log disk quota in MB.
                type: int
            onetime_schedule:
                description:
                    - Maximum number of firewall one-time schedules.
                type: int
            proxy:
                description:
                    - Maximum number of concurrent explicit proxy users.
                type: int
            recurring_schedule:
                description:
                    - Maximum number of firewall recurring schedules.
                type: int
            service_group:
                description:
                    - Maximum number of firewall service groups.
                type: int
            session:
                description:
                    - Maximum number of sessions.
                type: int
            user:
                description:
                    - Maximum number of local users.
                type: int
            user_group:
                description:
                    - Maximum number of user groups.
                type: int
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
  - name: Resource limits configuration.
    fortiswitch_system_resource_limits:
      system_resource_limits:
        custom_service: "3"
        dialup_tunnel: "4"
        firewall_address: "5"
        firewall_addrgrp: "6"
        firewall_policy: "7"
        ipsec_phase1: "8"
        ipsec_phase2: "9"
        log_disk_quota: "10"
        onetime_schedule: "11"
        proxy: "12"
        recurring_schedule: "13"
        service_group: "14"
        session: "15"
        user: "16"
        user_group: "17"

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


def filter_system_resource_limits_data(json):
    option_list = ['custom_service', 'dialup_tunnel', 'firewall_address',
                   'firewall_addrgrp', 'firewall_policy', 'ipsec_phase1',
                   'ipsec_phase2', 'log_disk_quota', 'onetime_schedule',
                   'proxy', 'recurring_schedule', 'service_group',
                   'session', 'user', 'user_group']

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


def system_resource_limits(data, fos):
    system_resource_limits_data = data['system_resource_limits']
    filtered_data = underscore_to_hyphen(filter_system_resource_limits_data(system_resource_limits_data))

    return fos.set('system',
                   'resource-limits',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):
    fos.do_member_operation('system', 'resource-limits')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_resource_limits']:
        resp = system_resource_limits(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_resource_limits'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "type": "dict",
    "children": {
        "service_group": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "firewall_address": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "firewall_policy": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "session": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "user": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "custom_service": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "ipsec_phase2": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "ipsec_phase1": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "log_disk_quota": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "dialup_tunnel": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "user_group": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "onetime_schedule": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "firewall_addrgrp": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "recurring_schedule": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "proxy": {
            "type": "integer",
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
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "system_resource_limits": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_resource_limits"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_resource_limits"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_resource_limits")
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
