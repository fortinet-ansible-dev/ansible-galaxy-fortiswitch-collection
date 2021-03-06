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
module: fortiswitch_switch_mirror
short_description: Packet mirror in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch feature and mirror category.
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
    switch_mirror:
        description:
            - Packet mirror.
        default: null
        type: dict
        suboptions:
            dst:
                description:
                    - Destination interface. Source switch.interface.name.
                type: str
            encap_gre_protocol:
                description:
                    - Protocol value in the ERSPAN GRE header.
                type: int
            encap_ipv4_src:
                description:
                    - IPv4 source address in the ERSPAN IP header.
                type: str
            encap_ipv4_tos:
                description:
                    - TOS, or DSCP and ECN, values in the ERSPAN IP header.
                type: int
            encap_ipv4_ttl:
                description:
                    - IPv4 time-to-live value in the ERSPAN IP header.
                type: int
            encap_mac_dst:
                description:
                    - Nexthop/Gateway MAC address on the path to the ERSPAN collector IP.
                type: str
            encap_mac_src:
                description:
                    - Source MAC address in the ERSPAN ethernet header.
                type: str
            encap_vlan:
                description:
                    - Control the tagged/untagged status of ERSPAN encapsulation headers.
                type: str
                choices:
                    - tagged
                    - untagged
            encap_vlan_cfi:
                description:
                    - CFI or DEI bit in the ERSPAN or RSPAN VLAN header.
                type: int
            encap_vlan_id:
                description:
                    - VLAN ID in the ERSPAN or RSPAN VLAN header.
                type: int
            encap_vlan_priority:
                description:
                    - Priority code point value in the ERSPAN or RSPAN VLAN header.
                type: int
            encap_vlan_tpid:
                description:
                    - TPID in the ERSPAN or RSPAN VLAN header.
                type: int
            erspan_collector_ip:
                description:
                    - ERSPAN collector IP address.
                type: str
            mode:
                description:
                    - Mirroring mode.
                type: str
                choices:
                    - SPAN
                    - RSPAN
                    - ERSPAN-manual
                    - ERSPAN-auto
            name:
                description:
                    - Mirror session name.
                required: true
                type: str
            rspan_ip:
                description:
                    - RSPAN destination IP address.
                type: str
            src_egress:
                description:
                    - Source egress interfaces.
                type: list
                suboptions:
                    name:
                        description:
                            - Interface name. Source switch.physical-port.name.
                        required: true
                        type: str
            src_ingress:
                description:
                    - Source ingress interfaces.
                type: list
                suboptions:
                    name:
                        description:
                            - Interface name. Source switch.physical-port.name.
                        required: true
                        type: str
            status:
                description:
                    - Status.
                type: str
                choices:
                    - active
                    - inactive
            strip_mirrored_traffic_tags:
                description:
                    - Enable/disable stripping of VLAN tags from mirrored traffic.
                type: str
                choices:
                    - enable
                    - disable
            switching_packet:
                description:
                    - Enable/disable switching functionality when mirroring.
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
  - name: Packet mirror.
    fortiswitch_switch_mirror:
      state: "present"
      switch_mirror:
        dst: "<your_own_value> (source switch.interface.name)"
        encap_gre_protocol: "4"
        encap_ipv4_src: "<your_own_value>"
        encap_ipv4_tos: "6"
        encap_ipv4_ttl: "7"
        encap_mac_dst: "<your_own_value>"
        encap_mac_src: "<your_own_value>"
        encap_vlan: "tagged"
        encap_vlan_cfi: "11"
        encap_vlan_id: "12"
        encap_vlan_priority: "13"
        encap_vlan_tpid: "14"
        erspan_collector_ip: "<your_own_value>"
        mode: "SPAN"
        name: "default_name_17"
        rspan_ip: "<your_own_value>"
        src_egress:
         -
            name: "default_name_20 (source switch.physical-port.name)"
        src_ingress:
         -
            name: "default_name_22 (source switch.physical-port.name)"
        status: "active"
        strip_mirrored_traffic_tags: "enable"
        switching_packet: "enable"

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


def filter_switch_mirror_data(json):
    option_list = ['dst', 'encap_gre_protocol', 'encap_ipv4_src',
                   'encap_ipv4_tos', 'encap_ipv4_ttl', 'encap_mac_dst',
                   'encap_mac_src', 'encap_vlan', 'encap_vlan_cfi',
                   'encap_vlan_id', 'encap_vlan_priority', 'encap_vlan_tpid',
                   'erspan_collector_ip', 'mode', 'name',
                   'rspan_ip', 'src_egress', 'src_ingress',
                   'status', 'strip_mirrored_traffic_tags', 'switching_packet']
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


def switch_mirror(data, fos):

    state = data['state']

    switch_mirror_data = data['switch_mirror']
    filtered_data = underscore_to_hyphen(filter_switch_mirror_data(switch_mirror_data))

    if state == "present" or state is True:
        return fos.set('switch',
                       'mirror',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('switch',
                          'mirror',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_switch(data, fos):

    fos.do_member_operation('switch_mirror')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_mirror']:
        resp = switch_mirror(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_mirror'))

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
                    "value": "active",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "inactive",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "encap_mac_src": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "encap_vlan_priority": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "encap_vlan_tpid": {
            "type": "integer",
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
        "encap_vlan": {
            "type": "string",
            "options": [
                {
                    "value": "tagged",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "untagged",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "strip_mirrored_traffic_tags": {
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
        "dst": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "encap_gre_protocol": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "erspan_collector_ip": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "encap_vlan_cfi": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "src_egress": {
            "type": "list",
            "children": {
                "name": {
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
        "encap_ipv4_src": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "encap_ipv4_tos": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "mode": {
            "type": "string",
            "options": [
                {
                    "value": "SPAN",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "RSPAN",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ERSPAN-manual",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ERSPAN-auto",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "rspan_ip": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "switching_packet": {
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
        "encap_ipv4_ttl": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "src_ingress": {
            "type": "list",
            "children": {
                "name": {
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
        "encap_vlan_id": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "encap_mac_dst": {
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
        "switch_mirror": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_mirror"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_mirror"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_mirror")

        is_error, has_changed, result = fortiswitch_switch(module.params, fos)

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
