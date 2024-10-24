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
module: fortiswitch_switch_mirror
short_description: Packet mirror in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch feature and mirror category.
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
    switch_mirror:
        description:
            - Packet mirror.
        default: null
        type: dict
        suboptions:
            dst:
                description:
                    - Destination interface.
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
                    - 'tagged'
                    - 'untagged'
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
                    - 'SPAN'
                    - 'RSPAN'
                    - 'ERSPAN-manual'
                    - 'ERSPAN-auto'
                    - 'RSPAN-manual'
                    - 'RSPAN-auto'
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
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name.
                        type: str
            src_ingress:
                description:
                    - Source ingress interfaces.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name.
                        type: str
            status:
                description:
                    - Status.
                type: str
                choices:
                    - 'active'
                    - 'inactive'
            strip_mirrored_traffic_tags:
                description:
                    - Enable/disable stripping of VLAN tags from mirrored traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switching_packet:
                description:
                    - Enable/disable switching functionality when mirroring.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
'''

EXAMPLES = '''
- name: Packet mirror.
  fortinet.fortiswitch.fortiswitch_switch_mirror:
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
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.data_post_processor import remove_invalid_fields
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import is_same_comparison
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import serialize
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import find_current_values


def filter_switch_mirror_data(json):
    option_list = ['dst', 'encap_gre_protocol', 'encap_ipv4_src',
                   'encap_ipv4_tos', 'encap_ipv4_ttl', 'encap_mac_dst',
                   'encap_mac_src', 'encap_vlan', 'encap_vlan_cfi',
                   'encap_vlan_id', 'encap_vlan_priority', 'encap_vlan_tpid',
                   'erspan_collector_ip', 'mode', 'name',
                   'rspan_ip', 'src_egress', 'src_ingress',
                   'status', 'strip_mirrored_traffic_tags', 'switching_packet']

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


def switch_mirror(data, fos, check_mode=False):
    state = data.get('state', None)

    switch_mirror_data = data['switch_mirror']

    filtered_data = filter_switch_mirror_data(switch_mirror_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('switch', 'mirror', filtered_data)
        current_data = fos.get('switch', 'mirror', mkey=mkey)
        is_existed = current_data and current_data.get('http_status') == 200 \
            and isinstance(current_data.get('results'), list) \
            and len(current_data['results']) > 0

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == 'present' or state is True or state is None:
            mkeyname = fos.get_mkeyname(None, None)
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)

            # handle global modules'
            if mkeyname is None and state is None:
                is_same = is_same_comparison(
                    serialize(current_data['results']), serialize(copied_filtered_data))

                current_values = find_current_values(copied_filtered_data, current_data['results'])

                return False, not is_same, filtered_data, {"before": current_values, "after": copied_filtered_data}

            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data['results'][0]), serialize(copied_filtered_data))

                current_values = find_current_values(copied_filtered_data, current_data['results'][0])

                return False, not is_same, filtered_data, {"before": current_values, "after": copied_filtered_data}

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


def fortiswitch_switch(data, fos, check_mode):
    fos.do_member_operation('switch', 'mirror')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_mirror']:
        resp = switch_mirror(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_mirror'))
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
            "help": "Status.",
            "category": "unitary"
        },
        "encap_vlan": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "tagged"
                },
                {
                    "value": "untagged"
                }
            ],
            "name": "encap-vlan",
            "help": "Control the tagged/untagged status of ERSPAN encapsulation headers.",
            "category": "unitary"
        },
        "encap_ipv4_tos": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "encap-ipv4-tos",
            "help": "TOS,or DSCP and ECN,values in the ERSPAN IP header.",
            "category": "unitary"
        },
        "erspan_collector_ip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "erspan-collector-ip",
            "help": "ERSPAN collector IP address.",
            "category": "unitary"
        },
        "switching_packet": {
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
            "name": "switching-packet",
            "help": "Enable/disable switching functionality when mirroring.",
            "category": "unitary"
        },
        "encap_vlan_priority": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "encap-vlan-priority",
            "help": "Priority code point value in the ERSPAN or RSPAN VLAN header.",
            "category": "unitary"
        },
        "dst": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "dst",
            "help": "Destination interface.",
            "category": "unitary"
        },
        "encap_gre_protocol": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "encap-gre-protocol",
            "help": "Protocol value in the ERSPAN GRE header.",
            "category": "unitary"
        },
        "src_egress": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "name",
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
            "name": "src-egress",
            "help": "Source egress interfaces.",
            "mkey": "name",
            "category": "table"
        },
        "encap_ipv4_ttl": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "encap-ipv4-ttl",
            "help": "IPv4 time-to-live value in the ERSPAN IP header.",
            "category": "unitary"
        },
        "encap_vlan_id": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "encap-vlan-id",
            "help": "VLAN ID in the ERSPAN or RSPAN VLAN header.",
            "category": "unitary"
        },
        "encap_vlan_tpid": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "encap-vlan-tpid",
            "help": "TPID in the ERSPAN or RSPAN VLAN header.",
            "category": "unitary"
        },
        "mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "SPAN"
                },
                {
                    "value": "RSPAN"
                },
                {
                    "value": "ERSPAN-manual"
                },
                {
                    "value": "ERSPAN-auto"
                },
                {
                    "value": "RSPAN-manual",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                },
                {
                    "value": "RSPAN-auto",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                }
            ],
            "name": "mode",
            "help": "Mirroring mode.",
            "category": "unitary"
        },
        "encap_mac_dst": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "encap-mac-dst",
            "help": "Nexthop/Gateway MAC address on the path to the ERSPAN collector IP.",
            "category": "unitary"
        },
        "src_ingress": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "name",
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
            "name": "src-ingress",
            "help": "Source ingress interfaces.",
            "mkey": "name",
            "category": "table"
        },
        "rspan_ip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "rspan-ip",
            "help": "RSPAN destination IP address.",
            "category": "unitary"
        },
        "encap_mac_src": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "encap-mac-src",
            "help": "Source MAC address in the ERSPAN ethernet header.",
            "category": "unitary"
        },
        "strip_mirrored_traffic_tags": {
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
            "name": "strip-mirrored-traffic-tags",
            "help": "Enable/disable stripping of VLAN tags from mirrored traffic.",
            "category": "unitary"
        },
        "encap_ipv4_src": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "encap-ipv4-src",
            "help": "IPv4 source address in the ERSPAN IP header.",
            "category": "unitary"
        },
        "encap_vlan_cfi": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "encap-vlan-cfi",
            "help": "CFI or DEI bit in the ERSPAN or RSPAN VLAN header.",
            "category": "unitary"
        },
        "name": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "name",
            "help": "Mirror session name.",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "name": "mirror",
    "help": "Packet mirror.",
    "mkey": "name",
    "category": "table"
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
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
        "switch_mirror": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_mirror"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_mirror"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_mirror")
        is_error, has_changed, result, diff = fortiswitch_switch(module.params, fos, module.check_mode)
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
