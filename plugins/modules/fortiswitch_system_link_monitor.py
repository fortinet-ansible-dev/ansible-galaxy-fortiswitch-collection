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
module: fortiswitch_system_link_monitor
short_description: Configure Link Health Monitor in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and link_monitor category.
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
    system_link_monitor:
        description:
            - Configure Link Health Monitor.
        default: null
        type: dict
        suboptions:
            addr_mode:
                description:
                    - Address mode (IPv4 or IPv6).
                type: str
                choices:
                    - ipv4
                    - ipv6
            failtime:
                description:
                    - Number of retry attempts before bringing server down.
                type: int
            gateway_ip:
                description:
                    - Gateway IP used to PING the server.
                type: str
            gateway_ip6:
                description:
                    - Gateway IPv6 address used to PING the server.
                type: str
            http_get:
                description:
                    - HTTP GET URL string.
                type: str
            http_match:
                description:
                    - Response value from detected server in http-get.
                type: str
            interval:
                description:
                    - Detection interval.
                type: int
            name:
                description:
                    - Link monitor name.
                required: true
                type: str
            packet_size:
                description:
                    - Packet size of a twamp test session,.
                type: int
            password:
                description:
                    - Twamp controller password in authentication mode.
                type: str
            port:
                description:
                    - Port number to poll.
                type: int
            protocol:
                description:
                    - Protocols used to detect the server.
                type: str
                choices:
                    - arp
                    - ping
                    - ping6
            recoverytime:
                description:
                    - Number of retry attempts before bringing server up.
                type: int
            security_mode:
                description:
                    - Twamp controller security mode.
                type: str
                choices:
                    - none
                    - authentication
            source_ip:
                description:
                    - Source IP used in packet to the server.
                type: str
            source_ip6:
                description:
                    - Source IPv6 address used in packet to the server.
                type: str
            srcintf:
                description:
                    - Interface where the monitor traffic is sent. Source system.interface.name.
                type: str
            status:
                description:
                    - Enable/disable link monitor administrative status.
                type: str
                choices:
                    - enable
                    - disable
            timeout:
                description:
                    - Detect request timeout.
                type: int
            update_cascade_interface:
                description:
                    - Enable/disable update cascade interface.
                type: str
                choices:
                    - enable
                    - disable
            update_static_route:
                description:
                    - Enable/disable update static route.
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
  - name: Configure Link Health Monitor.
    fortiswitch_system_link_monitor:
      state: "present"
      system_link_monitor:
        addr_mode: "ipv4"
        failtime: "4"
        gateway_ip: "<your_own_value>"
        gateway_ip6: "<your_own_value>"
        http_get: "<your_own_value>"
        http_match: "<your_own_value>"
        interval: "9"
        name: "default_name_10"
        packet_size: "11"
        password: "<your_own_value>"
        port: "13"
        protocol: "arp"
        recoverytime: "15"
        security_mode: "none"
        source_ip: "84.230.14.43"
        source_ip6: "<your_own_value>"
        srcintf: "<your_own_value> (source system.interface.name)"
        status: "enable"
        timeout: "21"
        update_cascade_interface: "enable"
        update_static_route: "enable"

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


def filter_system_link_monitor_data(json):
    option_list = ['addr_mode', 'failtime', 'gateway_ip',
                   'gateway_ip6', 'http_get', 'http_match',
                   'interval', 'name', 'packet_size',
                   'password', 'port', 'protocol',
                   'recoverytime', 'security_mode', 'source_ip',
                   'source_ip6', 'srcintf', 'status',
                   'timeout', 'update_cascade_interface', 'update_static_route']
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


def system_link_monitor(data, fos):

    state = data['state']

    system_link_monitor_data = data['system_link_monitor']
    filtered_data = underscore_to_hyphen(filter_system_link_monitor_data(system_link_monitor_data))

    if state == "present" or state is True:
        return fos.set('system',
                       'link-monitor',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system',
                          'link-monitor',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):

    fos.do_member_operation('system_link_monitor')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_link_monitor']:
        resp = system_link_monitor(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_link_monitor'))

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
        "http_match": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "password": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "protocol": {
            "type": "string",
            "options": [
                {
                    "value": "arp",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ping",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ping6",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
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
        "gateway_ip6": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "update_cascade_interface": {
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
        "interval": {
            "type": "integer",
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
        "port": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "failtime": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "srcintf": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "source_ip6": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "addr_mode": {
            "type": "string",
            "options": [
                {
                    "value": "ipv4",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ipv6",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "gateway_ip": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "timeout": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "update_static_route": {
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
        "packet_size": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "http_get": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "recoverytime": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "security_mode": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "authentication",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
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
        "system_link_monitor": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_link_monitor"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_link_monitor"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_link_monitor")

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
