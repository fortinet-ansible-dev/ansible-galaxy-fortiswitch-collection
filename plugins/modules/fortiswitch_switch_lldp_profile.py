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
module: fortiswitch_switch_lldp_profile
short_description: LLDP configuration profiles in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch_lldp feature and profile category.
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
    switch_lldp_profile:
        description:
            - LLDP configuration profiles.
        default: null
        type: dict
        suboptions:
            802.1_tlvs:
                description:
                    - Transmitted IEEE 802.1 TLVs.
                type: str
                choices:
                    - port-vlan-id
            802.3_tlvs:
                description:
                    - Transmitted IEEE 802.3 TLVs.
                type: str
                choices:
                    - max-frame-size
                    - power-negotiation
                    - eee-config
            auto_isl:
                description:
                    - Enable/disable automatic inter-switch LAG.
                type: str
                choices:
                    - enable
                    - disable
            auto_isl_hello_timer:
                description:
                    - Automatic ISL hello timer (1 - 30 sec).
                type: int
            auto_isl_port_group:
                description:
                    - Automatic inter-switch LAG port group.
                type: int
            auto_isl_receive_timeout:
                description:
                    - Automatic ISL timeout (0 - 300 sec).
                type: int
            auto_mclag_icl:
                description:
                    - Enable/disable MCLAG inter chassis link.
                type: str
                choices:
                    - enable
                    - disable
            custom_tlvs:
                description:
                    - Organizationally Specific TLV configuration.
                type: list
                suboptions:
                    information_string:
                        description:
                            - Organizationally defined information string.
                        type: str
                    name:
                        description:
                            - TLV name (not sent).
                        required: true
                        type: str
                    oui:
                        description:
                            - Organizationally unique identifier.
                        type: str
                    subtype:
                        description:
                            - Organizationally defined subtype.
                        type: int
            med_location_service:
                description:
                    - LLDP MED location service configuration.
                type: list
                suboptions:
                    name:
                        description:
                            - Policy type name.
                        required: true
                        type: str
                    status:
                        description:
                            - Enable/disable Location Service TLV.
                        type: str
                        choices:
                            - disable
                            - enable
                    sys_location_id:
                        description:
                            - LLDP System Location Id. Source system.location.name.
                        type: str
            med_network_policy:
                description:
                    - LLDP MED network policy configuration.
                type: list
                suboptions:
                    assign_vlan:
                        description:
                            - Enable/disable automatically adding this VLAN to ports with this profile (does not affect trunks).
                        type: str
                        choices:
                            - disable
                            - enable
                    dscp:
                        description:
                            - Advertised DSCP value.
                        type: int
                    name:
                        description:
                            - Policy type name.
                        required: true
                        type: str
                    priority:
                        description:
                            - Advertised L2 priority.
                        type: int
                    status:
                        description:
                            - Enable/disable this TLV.
                        type: str
                        choices:
                            - disable
                            - enable
                    vlan:
                        description:
                            - VLAN to advertise (if configured on port).
                        type: int
            med_tlvs:
                description:
                    - Transmitted LLDP-MED TLVs.
                type: str
                choices:
                    - inventory-management
                    - network-policy
                    - location-identification
                    - power-management
            name:
                description:
                    - Profile name.
                required: true
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
  - name: LLDP configuration profiles.
    fortiswitch_switch_lldp_profile:
      state: "present"
      switch_lldp_profile:
        802.1_tlvs: "port-vlan-id"
        802.3_tlvs: "max-frame-size"
        auto_isl: "enable"
        auto_isl_hello_timer: "6"
        auto_isl_port_group: "7"
        auto_isl_receive_timeout: "8"
        auto_mclag_icl: "enable"
        custom_tlvs:
         -
            information_string: "<your_own_value>"
            name: "default_name_12"
            oui: "<your_own_value>"
            subtype: "14"
        med_location_service:
         -
            name: "default_name_16"
            status: "disable"
            sys_location_id: "<your_own_value> (source system.location.name)"
        med_network_policy:
         -
            assign_vlan: "disable"
            dscp: "21"
            name: "default_name_22"
            priority: "23"
            status: "disable"
            vlan: "25"
        med_tlvs: "inventory-management"
        name: "default_name_27"

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


def filter_switch_lldp_profile_data(json):
    option_list = ['802.1_tlvs', '802.3_tlvs', 'auto_isl',
                   'auto_isl_hello_timer', 'auto_isl_port_group', 'auto_isl_receive_timeout',
                   'auto_mclag_icl', 'custom_tlvs', 'med_location_service',
                   'med_network_policy', 'med_tlvs', 'name']
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


def switch_lldp_profile(data, fos):

    state = data['state']

    switch_lldp_profile_data = data['switch_lldp_profile']
    filtered_data = underscore_to_hyphen(filter_switch_lldp_profile_data(switch_lldp_profile_data))

    if state == "present" or state is True:
        return fos.set('switch.lldp',
                       'profile',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('switch.lldp',
                          'profile',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_switch_lldp(data, fos):

    fos.do_member_operation('switch_lldp_profile')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_lldp_profile']:
        resp = switch_lldp_profile(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_lldp_profile'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "med_tlvs": {
            "type": "string",
            "options": [
                {
                    "value": "inventory-management",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "network-policy",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "location-identification",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "power-management",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "auto_mclag_icl": {
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
        "name": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "auto_isl_hello_timer": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "auto_isl": {
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
        "custom_tlvs": {
            "type": "list",
            "children": {
                "information_string": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "subtype": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "oui": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
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
        "med_network_policy": {
            "type": "list",
            "children": {
                "status": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "enable",
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
                "vlan": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "dscp": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "priority": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "assign_vlan": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "enable",
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
        },
        "auto_isl_port_group": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "auto_isl_receive_timeout": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "med_location_service": {
            "type": "list",
            "children": {
                "status": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "sys_location_id": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
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
        "802.3_tlvs": {
            "type": "string",
            "options": [
                {
                    "value": "max-frame-size",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "power-negotiation",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "eee-config",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "802.1_tlvs": {
            "type": "string",
            "options": [
                {
                    "value": "port-vlan-id",
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
        "switch_lldp_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_lldp_profile"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_lldp_profile"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_lldp_profile")

        is_error, has_changed, result = fortiswitch_switch_lldp(module.params, fos)

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
