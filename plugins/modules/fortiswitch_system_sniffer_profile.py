#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019-2020 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortiswitch_system_sniffer_profile
short_description: Show packet sniffer configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and sniffer_profile category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v7.0.0
version_added: "2.11"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:

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
    system_sniffer_profile:
        description:
            - Show packet sniffer configuration.
        default: null
        type: dict
        suboptions:
            filter:
                description:
                    - 'Flexible logical filters for sniffer (or "none")                    For example:  To print udp 1812 traffic between forti1 and either
                       forti2 or forti3                    "udp and port 1812 and host forti1 and \\( forti2 or forti3 \\)."'
                type: str
            max_pkt_count:
                description:
                    - Maximum number of packet to be captured on the interface  (1-INT_MAX).
                type: int
            max_pkt_len:
                description:
                    - Maximum packet length to be captured on the interface  (64-1534).
                type: int
            profile_name:
                description:
                    - Give name to the sniffer profile.
                type: str
            switch_interface:
                description:
                    - Select switch-interface name on which packets are to be captured. Source switch.interface.name.
                type: str
            system_interface:
                description:
                    - Select system-interface name on which packets are to be captured. Source system.interface.name.
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
  - name: Show packet sniffer configuration.
    fortiswitch_system_sniffer_profile:
      state: "present"
      system_sniffer_profile:
        filter: "<your_own_value>"
        max_pkt_count: "4"
        max_pkt_len: "5"
        profile_name: "<your_own_value>"
        switch_interface: "<your_own_value> (source switch.interface.name)"
        system_interface: "<your_own_value> (source system.interface.name)"

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


def filter_system_sniffer_profile_data(json):
    option_list = ['filter', 'max_pkt_count', 'max_pkt_len',
                   'profile_name', 'switch_interface', 'system_interface']
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


def system_sniffer_profile(data, fos):

    state = data['state']

    system_sniffer_profile_data = data['system_sniffer_profile']
    filtered_data = underscore_to_hyphen(filter_system_sniffer_profile_data(system_sniffer_profile_data))

    if state == "present" or state is True:
        return fos.set('system',
                       'sniffer-profile',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system',
                          'sniffer-profile',
                          mkey=filtered_data['profile-name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):

    fos.do_member_operation('system_sniffer_profile')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_sniffer_profile']:
        resp = system_sniffer_profile(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_sniffer_profile'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "max_pkt_count": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "system_interface": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "filter": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "profile_name": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "max_pkt_len": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "switch_interface": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        }
    },
    "revisions": {
        "v7.0.0": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'profile-name'
    fields = {
        "enable_log": {"required": False, "type": bool},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "system_sniffer_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_sniffer_profile"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_sniffer_profile"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_sniffer_profile")

        is_error, has_changed, result = fortiswitch_system(module.params, fos)

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortiSwitch system and your playbook, see more details by specifying option -vvv")

    if not is_error:
        if versions_check_result and versions_check_result['matched'] is False:
            module.exit_json(changed=has_changed, version_check_warning=versions_check_result, meta=result)
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        if versions_check_result and versions_check_result['matched'] is False:
            module.fail_json(msg="Error in repo", version_check_warning=versions_check_result, meta=result)
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
