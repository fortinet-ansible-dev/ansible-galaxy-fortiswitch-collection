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
module: fortiswitch_system_snmp_community
short_description: SNMP community configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system_snmp feature and community category.
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
    system_snmp_community:
        description:
            - SNMP community configuration.
        default: null
        type: dict
        suboptions:
            events:
                description:
                    - Trap snmp events.
                type: str
                choices:
                    - cpu-high
                    - mem-low
                    - log-full
                    - intf-ip
                    - ent-conf-change
            hosts:
                description:
                    - Allow hosts configuration.
                type: list
                suboptions:
                    id:
                        description:
                            - Host entry id.
                        required: true
                        type: int
                    interface:
                        description:
                            - Allow interface name. Source system.interface.name.
                        type: str
                    ip:
                        description:
                            - Allow host ip address and netmask.
                        type: str
                    source_ip:
                        description:
                            - Source ip for snmp trap.
                        type: str
            hosts6:
                description:
                    - Allow hosts configuration for IPv6.
                type: list
                suboptions:
                    id:
                        description:
                            - Host6 entry id.
                        required: true
                        type: int
                    interface:
                        description:
                            - Allow interface name. Source system.interface.name.
                        type: str
                    ipv6:
                        description:
                            - Allow host ipv6 address.
                        type: str
                    source_ipv6:
                        description:
                            - Source ipv6 for snmp trap.
                        type: str
            id:
                description:
                    - Community id.
                required: true
                type: int
            name:
                description:
                    - Community name.
                type: str
            query_v1_port:
                description:
                    - SNMP v1 query port.
                type: int
            query_v1_status:
                description:
                    - Enable/disable snmp v1 query.
                type: str
                choices:
                    - enable
                    - disable
            query_v2c_port:
                description:
                    - SNMP v2c query port.
                type: int
            query_v2c_status:
                description:
                    - Enable/disable snmp v2c query.
                type: str
                choices:
                    - enable
                    - disable
            status:
                description:
                    - Enable/disable this commuity.
                type: str
                choices:
                    - enable
                    - disable
            trap_v1_lport:
                description:
                    - SNMP v1 trap local port.
                type: int
            trap_v1_rport:
                description:
                    - SNMP v1 trap remote port.
                type: int
            trap_v1_status:
                description:
                    - Enable/disable snmp v1 trap.
                type: str
                choices:
                    - enable
                    - disable
            trap_v2c_lport:
                description:
                    - SNMP v2c trap local port.
                type: int
            trap_v2c_rport:
                description:
                    - SNMP v2c trap remote port.
                type: int
            trap_v2c_status:
                description:
                    - Enable/disable snmp v2c trap.
                type: str
                choices:
                    - enable
                    - disable
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
  - name: SNMP community configuration.
    fortiswitch_system_snmp_community:
      state: "present"
      system_snmp_community:
        events: "cpu-high"
        hosts:
         -
            id:  "5"
            interface: "<your_own_value> (source system.interface.name)"
            ip: "<your_own_value>"
            source_ip: "84.230.14.43"
        hosts6:
         -
            id:  "10"
            interface: "<your_own_value> (source system.interface.name)"
            ipv6: "<your_own_value>"
            source_ipv6: "<your_own_value>"
        id:  "14"
        name: "default_name_15"
        query_v1_port: "16"
        query_v1_status: "enable"
        query_v2c_port: "18"
        query_v2c_status: "enable"
        status: "enable"
        trap_v1_lport: "21"
        trap_v1_rport: "22"
        trap_v1_status: "enable"
        trap_v2c_lport: "24"
        trap_v2c_rport: "25"
        trap_v2c_status: "enable"

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


def filter_system_snmp_community_data(json):
    option_list = ['events', 'hosts', 'hosts6',
                   'id', 'name', 'query_v1_port',
                   'query_v1_status', 'query_v2c_port', 'query_v2c_status',
                   'status', 'trap_v1_lport', 'trap_v1_rport',
                   'trap_v1_status', 'trap_v2c_lport', 'trap_v2c_rport',
                   'trap_v2c_status']
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


def system_snmp_community(data, fos):

    state = data['state']

    system_snmp_community_data = data['system_snmp_community']
    filtered_data = underscore_to_hyphen(filter_system_snmp_community_data(system_snmp_community_data))

    if state == "present" or state is True:
        return fos.set('system.snmp',
                       'community',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system.snmp',
                          'community',
                          mkey=filtered_data['id'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system_snmp(data, fos):

    fos.do_member_operation('system_snmp_community')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_snmp_community']:
        resp = system_snmp_community(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_snmp_community'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "status": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "hosts6": {
            "type": "list",
            "children": {
                "interface": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "source_ipv6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ipv6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "query_v1_status": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "id": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "events": {
            "type": "string",
            "options": [
                {
                    "value": "cpu-high",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "mem-low",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "log-full",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "intf-ip",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ent-conf-change",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "trap_v2c_rport": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "query_v1_port": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "hosts": {
            "type": "list",
            "children": {
                "interface": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "source_ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        },
        "trap_v1_status": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "trap_v1_lport": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "trap_v2c_status": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "trap_v1_rport": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "query_v2c_status": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "trap_v2c_lport": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "query_v2c_port": {
            "type": "integer",
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
    mkeyname = 'id'
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
        "system_snmp_community": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_snmp_community"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_snmp_community"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_snmp_community")

        is_error, has_changed, result = fortiswitch_system_snmp(module.params, fos)

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
