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
module: fortiswitch_switch_acl_egress
short_description: Egress Policy configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch_acl feature and egress category.
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
    switch_acl_egress:
        description:
            - Egress Policy configuration.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Actions for the policy.
                type: dict
                suboptions:
                    count:
                        description:
                            - Count enable/disable action.
                        type: str
                        choices:
                            - enable
                            - disable
                    drop:
                        description:
                            - Drop enable/disable action.
                        type: str
                        choices:
                            - enable
                            - disable
                    mirror:
                        description:
                            - Mirror session name. Source switch.mirror.name.
                        type: str
                    outer_vlan_tag:
                        description:
                            - Outer vlan tag.
                        type: int
                    policer:
                        description:
                            - Policer id. Source switch.acl.policer.id.
                        type: int
                    redirect:
                        description:
                            - Redirect interface name. Source switch.physical-port.name switch.trunk.name.
                        type: str
                    remark_dscp:
                        description:
                            - Remark DSCP value (0 - 63), or unset to disable.
                        type: int
            classifier:
                description:
                    - Match-conditions for the policy.
                type: dict
                suboptions:
                    cos:
                        description:
                            - 802.1Q CoS value to be matched.
                        type: int
                    dscp:
                        description:
                            - DSCP value to be matched.
                        type: int
                    dst_ip_prefix:
                        description:
                            - Destination-ip address to be matched.
                        type: str
                    dst_mac:
                        description:
                            - Destination mac address to be matched.
                        type: str
                    ether_type:
                        description:
                            - Ether type to be matched.
                        type: int
                    service:
                        description:
                            - Service name. Source switch.acl.service.custom.name.
                        type: str
                    src_ip_prefix:
                        description:
                            - Source-ip address to be matched.
                        type: str
                    src_mac:
                        description:
                            - Source mac address to be matched.
                        type: str
                    vlan_id:
                        description:
                            - Vlan id to be matched.
                        type: int
            description:
                description:
                    - Description of the policy.
                type: str
            group:
                description:
                    - Group ID of the policy.
                type: int
            id:
                description:
                    - Egress policy ID.
                required: true
                type: int
            interface:
                description:
                    - Interface to which policy is bound on the egress. Source switch.physical-port.name.
                type: str
            schedule:
                description:
                    - schedule list.
                type: list
                suboptions:
                    schedule_name:
                        description:
                            - Schedule name. Source system.schedule.onetime.name system.schedule.recurring.name system.schedule.group.name.
                        type: str
            status:
                description:
                    - Set policy status.
                type: str
                choices:
                    - active
                    - inactive
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
  - name: Egress Policy configuration.
    fortiswitch_switch_acl_egress:
      state: "present"
      switch_acl_egress:
        action:
            count: "enable"
            drop: "enable"
            mirror: "<your_own_value> (source switch.mirror.name)"
            outer_vlan_tag: "7"
            policer: "8 (source switch.acl.policer.id)"
            redirect: "<your_own_value> (source switch.physical-port.name switch.trunk.name)"
            remark_dscp: "10"
        classifier:
            cos: "12"
            dscp: "13"
            dst_ip_prefix: "<your_own_value>"
            dst_mac: "<your_own_value>"
            ether_type: "16"
            service: "<your_own_value> (source switch.acl.service.custom.name)"
            src_ip_prefix: "<your_own_value>"
            src_mac: "<your_own_value>"
            vlan_id: "20"
        description: "<your_own_value>"
        group: "22"
        id:  "23"
        interface: "<your_own_value> (source switch.physical-port.name)"
        schedule:
         -
            schedule_name: "<your_own_value> (source system.schedule.onetime.name system.schedule.recurring.name system.schedule.group.name)"
        status: "active"

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


def filter_switch_acl_egress_data(json):
    option_list = ['action', 'classifier', 'description',
                   'group', 'id', 'interface',
                   'schedule', 'status']
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


def switch_acl_egress(data, fos):

    state = data['state']

    switch_acl_egress_data = data['switch_acl_egress']
    filtered_data = underscore_to_hyphen(filter_switch_acl_egress_data(switch_acl_egress_data))

    if state == "present" or state is True:
        return fos.set('switch.acl',
                       'egress',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('switch.acl',
                          'egress',
                          mkey=filtered_data['id'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_switch_acl(data, fos):

    fos.do_member_operation('switch_acl_egress')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_acl_egress']:
        resp = switch_acl_egress(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_acl_egress'))

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
        "group": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "description": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "schedule": {
            "type": "list",
            "children": {
                "schedule_name": {
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
        "id": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "interface": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "action": {
            "type": "dict",
            "children": {
                "count": {
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
                "redirect": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "drop": {
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
                "outer_vlan_tag": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "policer": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "remark_dscp": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "mirror": {
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
        "classifier": {
            "type": "dict",
            "children": {
                "dst_mac": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ether_type": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "service": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "cos": {
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
                "dst_ip_prefix": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "src_ip_prefix": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "src_mac": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vlan_id": {
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
        "switch_acl_egress": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_acl_egress"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_acl_egress"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_acl_egress")

        is_error, has_changed, result = fortiswitch_switch_acl(module.params, fos)

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
