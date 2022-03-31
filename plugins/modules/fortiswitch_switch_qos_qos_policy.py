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
module: fortiswitch_switch_qos_qos_policy
short_description: QOS egress policy in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch_qos feature and qos_policy category.
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
    switch_qos_qos_policy:
        description:
            - QOS egress policy.
        default: null
        type: dict
        suboptions:
            cos_queue:
                description:
                    - COS queue configuration.
                type: list
                suboptions:
                    description:
                        description:
                            - Description of the COS queue.
                        type: str
                    drop_policy:
                        description:
                            - COS queue drop policy.
                        type: str
                        choices:
                            - taildrop
                            - weighted-random-early-detection
                    ecn:
                        description:
                            - Update frame IP ECN field in lieu of packet drop.
                        type: str
                        choices:
                            - disable
                            - enable
                    max_rate:
                        description:
                            - Maximum rate (kbps). 0 to disable.
                        type: int
                    max_rate_percent:
                        description:
                            - Maximum rate (% of link speed).
                        type: int
                    min_rate:
                        description:
                            - Minimum rate (kbps). 0 to disable.
                        type: int
                    min_rate_percent:
                        description:
                            - Minimum rate (% of link speed).
                        type: int
                    name:
                        description:
                            - COS queue ID.
                        required: true
                        type: str
                    weight:
                        description:
                            - Weight of weighted round robin scheduling.
                        type: int
                    wred_slope:
                        description:
                            - Slope of WRED drop probability.
                        type: int
            name:
                description:
                    - QOS policy name.
                required: true
                type: str
            rate_by:
                description:
                    - COS queue rate by kbps or percent.
                type: str
                choices:
                    - kbps
                    - percent
            schedule:
                description:
                    - COS queue scheduling.
                type: str
                choices:
                    - strict
                    - round-robin
                    - weighted
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
  - name: QOS egress policy.
    fortiswitch_switch_qos_qos_policy:
      state: "present"
      switch_qos_qos_policy:
        cos_queue:
         -
            description: "<your_own_value>"
            drop_policy: "taildrop"
            ecn: "disable"
            max_rate: "7"
            max_rate_percent: "8"
            min_rate: "9"
            min_rate_percent: "10"
            name: "default_name_11"
            weight: "12"
            wred_slope: "13"
        name: "default_name_14"
        rate_by: "kbps"
        schedule: "strict"

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
def filter_switch_qos_qos_policy_data(json):
    option_list = ['cos_queue', 'name', 'rate_by',
                   'schedule' ]
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

def switch_qos_qos_policy(data, fos):
    
    state = data['state']
    
    switch_qos_qos_policy_data = data['switch_qos_qos_policy']
    filtered_data = underscore_to_hyphen(filter_switch_qos_qos_policy_data(switch_qos_qos_policy_data))

    
    if state == "present" or state is True:
        return fos.set('switch.qos',
                       'qos-policy',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('switch.qos',
                          'qos-policy',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')
    

def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404




def fortiswitch_switch_qos(data, fos):

    fos.do_member_operation('switch_qos_qos_policy')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_qos_qos_policy']:
        resp = switch_qos_qos_policy(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_qos_qos_policy'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp



versioned_schema = {
    "type": "list", 
    "children": {
        "cos_queue": {
            "type": "list", 
            "children": {
                "name": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "weight": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "min_rate": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "ecn": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "disable", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "enable", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }
                    ], 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "max_rate": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "max_rate_percent": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "drop_policy": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "taildrop", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "weighted-random-early-detection", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }
                    ], 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "min_rate_percent": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "wred_slope": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "description": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }
            }, 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "rate_by": {
            "type": "string", 
            "options": [
                {
                    "value": "kbps", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "percent", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }
            ], 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "name": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "schedule": {
            "type": "string", 
            "options": [
                {
                    "value": "strict", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "round-robin", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "weighted", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }
            ], 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }
    }, 
    "revisions": {
        "v7.0.3": True, 
        "v7.0.2": True, 
        "v7.0.1": True, 
        "v7.0.0": True
    }
}

def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'name'
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
        "switch_qos_qos_policy": {
            "required": False, "type": "dict", "default": None,
            "options": { 
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_qos_qos_policy"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_qos_qos_policy"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_qos_qos_policy")
        
        is_error, has_changed, result = fortiswitch_switch_qos(module.params, fos)
        
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