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
module: fortiswitch_system_flow_export
short_description: System Flow Export settings in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and flow_export category.
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
    
    system_flow_export:
        description:
            - System Flow Export settings.
        default: null
        type: dict
        suboptions:
            aggregates:
                description:
                    - Aggregates.
                type: list
                suboptions:
                    id:
                        description:
                            - Aggregate id.
                        required: true
                        type: int
                    ip:
                        description:
                            - Aggregate"s IP and Mask.
                        type: str
            collectors:
                description:
                    - Collectors.
                type: list
                suboptions:
                    ip:
                        description:
                            - IP address.
                        type: str
                    name:
                        description:
                            - Collector name.
                        required: true
                        type: str
                    port:
                        description:
                            - 'Port number (0-65535).'
                        type: int
                    transport:
                        description:
                            - Export transport (udp|tcp|sctp).
                        type: str
                        choices:
                            - udp
                            - tcp
                            - sctp
            filter:
                description:
                    - Filter (BPF).
                type: str
            format:
                description:
                    - Export Format (netflow1|netflow5|netflow9|ipfix).
                type: str
                choices:
                    - netflow1
                    - netflow5
                    - netflow9
                    - ipfix
            identity:
                description:
                    - Set identity of switch (0x00000000-0xFFFFFFFF ).
                type: int
            level:
                description:
                    - Export Level (vlan|ip|port|protocol|mac).
                type: str
                choices:
                    - mac
                    - ip
                    - proto
                    - port
                    - vlan
            max_export_pkt_size:
                description:
                    - Max Export Packet Size (512-9216).
                type: int
            template_export_period:
                description:
                    - Template export period in minutes (1-60).
                type: int
            timeout_general:
                description:
                    - Flow Session General Timeout (60-604800).
                type: int
            timeout_icmp:
                description:
                    - Flow Session ICMP Timeout (60-604800).
                type: int
            timeout_max:
                description:
                    - Flow Session MAX Timeout (60-604800).
                type: int
            timeout_tcp:
                description:
                    - Flow Session TCP Timeout (60-604800).
                type: int
            timeout_tcp_fin:
                description:
                    - Flow Session TCP Fin Timeout (60-604800).
                type: int
            timeout_tcp_rst:
                description:
                    - Flow Session TCP Reset Timeout (60-604800).
                type: int
            timeout_udp:
                description:
                    - Flow Session UDP Timeout (60-604800).
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
  - name: System Flow Export settings.
    fortiswitch_system_flow_export:
      state: "present"
      system_flow_export:
        aggregates:
         -
            id:  "4"
            ip: "<your_own_value>"
        collectors:
         -
            ip: "<your_own_value>"
            name: "default_name_8"
            port: "9"
            transport: "udp"
        filter: "<your_own_value>"
        format: "netflow1"
        identity: "13"
        level: "mac"
        max_export_pkt_size: "15"
        template_export_period: "16"
        timeout_general: "17"
        timeout_icmp: "18"
        timeout_max: "19"
        timeout_tcp: "20"
        timeout_tcp_fin: "21"
        timeout_tcp_rst: "22"
        timeout_udp: "23"

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
def filter_system_flow_export_data(json):
    option_list = ['aggregates', 'collectors', 'filter',
                   'format', 'identity', 'level',
                   'max_export_pkt_size', 'template_export_period', 'timeout_general',
                   'timeout_icmp', 'timeout_max', 'timeout_tcp',
                   'timeout_tcp_fin', 'timeout_tcp_rst', 'timeout_udp' ]
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

def system_flow_export(data, fos):
    system_flow_export_data = data['system_flow_export']
    filtered_data = underscore_to_hyphen(filter_system_flow_export_data(system_flow_export_data))

    
    return fos.set('system',
                    'flow-export',
                    data=filtered_data,
                    )
    

def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404




def fortiswitch_system(data, fos):

    fos.do_member_operation('system_flow_export')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_flow_export']:
        resp = system_flow_export(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_flow_export'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp



versioned_schema = {
    "type": "dict", 
    "children": {
        "timeout_tcp_rst": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "timeout_tcp": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "timeout_tcp_fin": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "collectors": {
            "type": "list", 
            "children": {
                "ip": {
                    "type": "string", 
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
                "transport": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "udp", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "tcp", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "sctp", 
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
                "port": {
                    "type": "integer", 
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
        "level": {
            "type": "string", 
            "options": [
                {
                    "value": "mac", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "ip", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "proto", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "port", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "vlan", 
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
        "aggregates": {
            "type": "list", 
            "children": {
                "ip": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "id": {
                    "type": "integer", 
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
        "format": {
            "type": "string", 
            "options": [
                {
                    "value": "netflow1", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "netflow5", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "netflow9", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "ipfix", 
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
        "timeout_max": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "filter": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "template_export_period": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "identity": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "timeout_general": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "max_export_pkt_size": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "timeout_udp": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "timeout_icmp": {
            "type": "integer", 
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
    mkeyname = None
    fields = {
        "enable_log": {"required": False, "type": bool},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "system_flow_export": {
            "required": False, "type": "dict", "default": None,
            "options": { 
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_flow_export"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_flow_export"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_flow_export")
        
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