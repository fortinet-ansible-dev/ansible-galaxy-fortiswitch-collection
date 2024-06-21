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
module: fortiswitch_switch_acl_ingress
short_description: Ingress Policy configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch_acl feature and ingress category.
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
    switch_acl_ingress:
        description:
            - Ingress Policy configuration.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Actions for the policy.
                type: dict
                suboptions:
                    cos_queue:
                        description:
                            - COS queue number (0 - 7), or unset to disable.
                        type: int
                    count:
                        description:
                            - Count enable/disable action.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    count_type:
                        description:
                            - 'Count-type(two colors): all, green, yellow, or red.'
                        type: str
                        choices:
                            - 'all'
                            - 'green'
                            - 'yellow'
                            - 'red'
                    cpu_cos_queue:
                        description:
                            - CPU COS queue number(17 - 25). Only if packets reach to CPU.
                        type: int
                    drop:
                        description:
                            - Drop enable/disable action.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    egress_mask:
                        description:
                            - List of physical ports to be configured in egress mask.
                        type: list
                        elements: dict
                        suboptions:
                            member_name:
                                description:
                                    - Physical port name.
                                type: str
                    mirror:
                        description:
                            - Mirror session name.
                        type: str
                    outer_vlan_tag:
                        description:
                            - Outer vlan tag.
                        type: int
                    policer:
                        description:
                            - Policer id.
                        type: int
                    redirect:
                        description:
                            - Redirect interface name.
                        type: str
                    redirect_bcast_cpu:
                        description:
                            - Redirect broadcast to all ports including CPU.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    redirect_bcast_no_cpu:
                        description:
                            - Redirect broadcast to all ports excluding CPU.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    redirect_physical_port:
                        description:
                            - List of physical ports to redirect.
                        type: list
                        elements: dict
                        suboptions:
                            member_name:
                                description:
                                    - Physical port name.
                                type: str
                    remark_cos:
                        description:
                            - Remark CoS value (0 - 7), or unset to disable.
                        type: int
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
                    dst_ip6_prefix:
                        description:
                            - Destination-ip6 address to be matched.
                        type: str
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
                            - Service name.
                        type: str
                    src_ip6_prefix:
                        description:
                            - Source-ip6 address to be matched.
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
                    - Ingress policy ID.
                required: true
                type: int
            ingress_interface:
                description:
                    - Interface list to which policy is bound on the ingress.
                type: list
                elements: dict
                suboptions:
                    member_name:
                        description:
                            - Interface name.
                        type: str
            ingress_interface_all:
                description:
                    - Select all interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            schedule:
                description:
                    - schedule list.
                type: list
                elements: dict
                suboptions:
                    schedule_name:
                        description:
                            - Schedule name.
                        type: str
            status:
                description:
                    - Set policy status.
                type: str
                choices:
                    - 'active'
                    - 'inactive'
'''

EXAMPLES = '''
- name: Ingress Policy configuration.
  fortinet.fortiswitch.fortiswitch_switch_acl_ingress:
      state: "present"
      switch_acl_ingress:
          action:
              cos_queue: "4"
              count: "enable"
              count_type: "all"
              cpu_cos_queue: "7"
              drop: "enable"
              egress_mask:
                  -
                      member_name: "<your_own_value> (source switch.physical-port.name)"
              mirror: "<your_own_value> (source switch.mirror.name)"
              outer_vlan_tag: "12"
              policer: "13 (source switch.acl.policer.id)"
              redirect: "<your_own_value> (source switch.physical-port.name switch.trunk.name)"
              redirect_bcast_cpu: "enable"
              redirect_bcast_no_cpu: "enable"
              redirect_physical_port:
                  -
                      member_name: "<your_own_value> (source switch.physical-port.name)"
              remark_cos: "19"
              remark_dscp: "20"
          classifier:
              cos: "22"
              dscp: "23"
              dst_ip6_prefix: "<your_own_value>"
              dst_ip_prefix: "<your_own_value>"
              dst_mac: "<your_own_value>"
              ether_type: "27"
              service: "<your_own_value> (source switch.acl.service.custom.name)"
              src_ip6_prefix: "<your_own_value>"
              src_ip_prefix: "<your_own_value>"
              src_mac: "<your_own_value>"
              vlan_id: "32"
          description: "<your_own_value>"
          group: "34"
          id: "35"
          ingress_interface:
              -
                  member_name: "<your_own_value> (source switch.physical-port.name switch.trunk.name)"
          ingress_interface_all: "enable"
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
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.data_post_processor import remove_invalid_fields
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import is_same_comparison
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import serialize


def filter_switch_acl_ingress_data(json):
    option_list = ['action', 'classifier', 'description',
                   'group', 'id', 'ingress_interface',
                   'ingress_interface_all', 'schedule', 'status']

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


def switch_acl_ingress(data, fos, check_mode=False):
    state = data['state']
    switch_acl_ingress_data = data['switch_acl_ingress']
    filtered_data = underscore_to_hyphen(filter_switch_acl_ingress_data(switch_acl_ingress_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('switch.acl', 'ingress', filtered_data)
        current_data = fos.get('switch.acl', 'ingress', mkey=mkey)
        is_existed = current_data and current_data.get('http_status') == 200 \
            and isinstance(current_data.get('results'), list) \
            and len(current_data['results']) > 0

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == 'present' or state is True:
            if mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data['results'][0]), serialize(filtered_data))
                return False, not is_same, filtered_data, {"before": current_data['results'][0], "after": filtered_data}

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
        return fos.set('switch.acl',
                       'ingress',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('switch.acl',
                          'ingress',
                          mkey=filtered_data['id'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_switch_acl(data, fos, check_mode):
    fos.do_member_operation('switch.acl', 'ingress')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_acl_ingress']:
        resp = switch_acl_ingress(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_acl_ingress'))
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
        "status": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "active"
                },
                {
                    "value": "inactive"
                }
            ],
            "name": "status",
            "help": "Set policy status.",
            "category": "unitary"
        },
        "ingress_interface_all": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "ingress-interface-all",
            "help": "Select all interface.",
            "category": "unitary"
        },
        "description": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "description",
            "help": "Description of the policy.",
            "category": "unitary"
        },
        "schedule": {
            "type": "list",
            "elements": "dict",
            "children": {
                "schedule_name": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "schedule-name",
                    "help": "Schedule name.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "schedule",
            "help": "schedule list.",
            "mkey": "schedule-name",
            "category": "table"
        },
        "ingress_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "member_name": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "member-name",
                    "help": "Interface name.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "ingress-interface",
            "help": "Interface list to which policy is bound on the ingress.",
            "mkey": "member-name",
            "category": "table"
        },
        "classifier": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "dict",
            "children": {
                "dst_mac": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "dst-mac",
                    "help": "Destination mac address to be matched.",
                    "category": "unitary"
                },
                "cos": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "cos",
                    "help": "802.1Q CoS value to be matched.",
                    "category": "unitary"
                },
                "service": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "service",
                    "help": "Service name.",
                    "category": "unitary"
                },
                "dst_ip_prefix": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "dst-ip-prefix",
                    "help": "Destination-ip address to be matched.",
                    "category": "unitary"
                },
                "src_mac": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "src-mac",
                    "help": "Source mac address to be matched.",
                    "category": "unitary"
                },
                "dscp": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "dscp",
                    "help": "DSCP value to be matched.",
                    "category": "unitary"
                },
                "ether_type": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ether-type",
                    "help": "Ether type to be matched.",
                    "category": "unitary"
                },
                "vlan_id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "vlan-id",
                    "help": "Vlan id to be matched.",
                    "category": "unitary"
                },
                "src_ip_prefix": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "src-ip-prefix",
                    "help": "Source-ip address to be matched.",
                    "category": "unitary"
                },
                "dst_ip6_prefix": {
                    "v_range": [
                        [
                            "v7.2.3",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "dst-ip6-prefix",
                    "help": "Destination-ip6 address to be matched.",
                    "category": "unitary"
                },
                "src_ip6_prefix": {
                    "v_range": [
                        [
                            "v7.2.3",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "src-ip6-prefix",
                    "help": "Source-ip6 address to be matched.",
                    "category": "unitary"
                }
            },
            "name": "classifier",
            "help": "Match-conditions for the policy.",
            "category": "complex"
        },
        "action": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "dict",
            "children": {
                "count": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "count",
                    "help": "Count enable/disable action.",
                    "category": "unitary"
                },
                "redirect": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "redirect",
                    "help": "Redirect interface name.",
                    "category": "unitary"
                },
                "redirect_bcast_cpu": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "redirect-bcast-cpu",
                    "help": "Redirect broadcast to all ports including CPU.",
                    "category": "unitary"
                },
                "redirect_physical_port": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "member_name": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "name": "member-name",
                            "help": "Physical port name.",
                            "category": "unitary"
                        }
                    },
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "name": "redirect-physical-port",
                    "help": "List of physical ports to redirect.",
                    "mkey": "member-name",
                    "category": "table"
                },
                "cos_queue": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "cos-queue",
                    "help": "COS queue number (0 - 7),or unset to disable.",
                    "category": "unitary"
                },
                "remark_dscp": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "remark-dscp",
                    "help": "Remark DSCP value (0 - 63),or unset to disable.",
                    "category": "unitary"
                },
                "egress_mask": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "member_name": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "name": "member-name",
                            "help": "Physical port name.",
                            "category": "unitary"
                        }
                    },
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "name": "egress-mask",
                    "help": "List of physical ports to be configured in egress mask.",
                    "mkey": "member-name",
                    "category": "table"
                },
                "drop": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "drop",
                    "help": "Drop enable/disable action.",
                    "category": "unitary"
                },
                "redirect_bcast_no_cpu": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "redirect-bcast-no-cpu",
                    "help": "Redirect broadcast to all ports excluding CPU.",
                    "category": "unitary"
                },
                "policer": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "policer",
                    "help": "Policer id.",
                    "category": "unitary"
                },
                "remark_cos": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "remark-cos",
                    "help": "Remark CoS value (0 - 7),or unset to disable.",
                    "category": "unitary"
                },
                "mirror": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "mirror",
                    "help": "Mirror session name.",
                    "category": "unitary"
                },
                "cpu_cos_queue": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "cpu-cos-queue",
                    "help": "CPU COS queue number(17 - 25). Only if packets reach to CPU.",
                    "category": "unitary"
                },
                "outer_vlan_tag": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "outer-vlan-tag",
                    "help": "Outer vlan tag.",
                    "category": "unitary"
                },
                "count_type": {
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "all"
                        },
                        {
                            "value": "green"
                        },
                        {
                            "value": "yellow"
                        },
                        {
                            "value": "red"
                        }
                    ],
                    "name": "count-type",
                    "help": "Count-type(two colors): all,green,yellow,or red.",
                    "category": "unitary"
                }
            },
            "name": "action",
            "help": "Actions for the policy.",
            "category": "complex"
        },
        "group": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "group",
            "help": "Group ID of the policy.",
            "category": "unitary"
        },
        "id": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "id",
            "help": "Ingress policy ID.",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "name": "ingress",
    "help": "Ingress Policy configuration.",
    "mkey": "id",
    "category": "table"
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    # mkeyname = None
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
        "switch_acl_ingress": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_acl_ingress"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_acl_ingress"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_acl_ingress")
        is_error, has_changed, result, diff = fortiswitch_switch_acl(module.params, fos, module.check_mode)
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
