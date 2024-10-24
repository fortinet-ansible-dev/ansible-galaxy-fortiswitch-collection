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
module: fortiswitch_system_settings
short_description: Settings in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and settings category.
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

    system_settings:
        description:
            - Settings.
        default: null
        type: dict
        suboptions:
            allow_subnet_overlap:
                description:
                    - Allow one interface subnet overlap with other interfaces.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            asymroute:
                description:
                    - Asymmetric route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            asymroute6:
                description:
                    - Asymmetric route6.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bfd:
                description:
                    - Enable Bidirectional Forwarding Detection (BFD) on all interfaces.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bfd_desired_min_tx:
                description:
                    - BFD desired minimal tx interval.
                type: int
            bfd_detect_mult:
                description:
                    - BFD detection multiplier.
                type: int
            bfd_dont_enforce_src_port:
                description:
                    - Verify Source Port of BFD Packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bfd_required_min_rx:
                description:
                    - BFD required minimal rx interval.
                type: int
            comments:
                description:
                    - Vd comments.
                type: str
            device:
                description:
                    - Interface.
                type: str
            ecmp_max_paths:
                description:
                    - Maximum number of ECMP next-hops.
                type: int
            gateway:
                description:
                    - Default gateway ip address.
                type: str
            ip:
                description:
                    - IP address and netmask.
                type: str
            ip_ecmp_mode:
                description:
                    - IP ecmp mode.
                type: str
                choices:
                    - 'source-ip-based'
                    - 'dst-ip-based'
                    - 'port-based'
            manageip:
                description:
                    - IP address and netmask.
                type: str
            multicast_forward:
                description:
                    - Multicast forwarding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            multicast_skip_policy:
                description:
                    - Skip policy check, and allow multicast through.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            multicast_ttl_notchange:
                description:
                    - Multicast ttl not change.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            opmode:
                description:
                    - Firewall operation mode.
                type: str
                choices:
                    - 'nat'
            per_ip_bandwidth:
                description:
                    - Per-ip-bandwidth disable.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            sccp_port:
                description:
                    - TCP port the SCCP proxy will monitor for SCCP traffic.
                type: int
            sip_helper:
                description:
                    - Helper to add dynamic sip firewall allow rule.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sip_nat_trace:
                description:
                    - Add original IP if NATed.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sip_tcp_port:
                description:
                    - TCP port the SIP proxy will monitor for SIP traffic.
                type: int
            sip_udp_port:
                description:
                    - UDP port the SIP proxy will monitor for SIP traffic.
                type: int
            status:
                description:
                    - Enable/disable this VDOM.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strict_src_check:
                description:
                    - Strict source verification.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            utf8_spam_tagging:
                description:
                    - Convert spam tags to UTF8 for better non-ascii character support.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vpn_stats_log:
                description:
                    - Enable periodic VPN log statistics.
                type: str
                choices:
                    - 'ipsec'
                    - 'pptp'
                    - 'l2tp'
                    - 'ssl'
            vpn_stats_period:
                description:
                    - Period to send VPN log statistics (seconds).
                type: int
            wccp_cache_engine:
                description:
                    - Enable wccp cache engine or not.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
'''

EXAMPLES = '''
- name: Settings.
  fortinet.fortiswitch.fortiswitch_system_settings:
      system_settings:
          allow_subnet_overlap: "enable"
          asymroute: "enable"
          asymroute6: "enable"
          bfd: "enable"
          bfd_desired_min_tx: "7"
          bfd_detect_mult: "8"
          bfd_dont_enforce_src_port: "enable"
          bfd_required_min_rx: "10"
          comments: "<your_own_value>"
          device: "<your_own_value> (source system.interface.name)"
          ecmp_max_paths: "13"
          gateway: "<your_own_value>"
          ip: "<your_own_value>"
          ip_ecmp_mode: "source-ip-based"
          manageip: "<your_own_value>"
          multicast_forward: "enable"
          multicast_skip_policy: "enable"
          multicast_ttl_notchange: "enable"
          opmode: "nat"
          per_ip_bandwidth: "disable"
          sccp_port: "23"
          sip_helper: "enable"
          sip_nat_trace: "enable"
          sip_tcp_port: "26"
          sip_udp_port: "27"
          status: "enable"
          strict_src_check: "enable"
          utf8_spam_tagging: "enable"
          vpn_stats_log: "ipsec"
          vpn_stats_period: "32"
          wccp_cache_engine: "enable"
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


def filter_system_settings_data(json):
    option_list = ['allow_subnet_overlap', 'asymroute', 'asymroute6',
                   'bfd', 'bfd_desired_min_tx', 'bfd_detect_mult',
                   'bfd_dont_enforce_src_port', 'bfd_required_min_rx', 'comments',
                   'device', 'ecmp_max_paths', 'gateway',
                   'ip', 'ip_ecmp_mode', 'manageip',
                   'multicast_forward', 'multicast_skip_policy', 'multicast_ttl_notchange',
                   'opmode', 'per_ip_bandwidth', 'sccp_port',
                   'sip_helper', 'sip_nat_trace', 'sip_tcp_port',
                   'sip_udp_port', 'status', 'strict_src_check',
                   'utf8_spam_tagging', 'vpn_stats_log', 'vpn_stats_period',
                   'wccp_cache_engine']

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


def system_settings(data, fos, check_mode=False):
    state = data.get('state', None)

    system_settings_data = data['system_settings']

    filtered_data = filter_system_settings_data(system_settings_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('system', 'settings', filtered_data)
        current_data = fos.get('system', 'settings', mkey=mkey)
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

    return fos.set('system',
                   'settings',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos, check_mode):
    fos.do_member_operation('system', 'settings')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_settings']:
        resp = system_settings(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_settings'))
    if check_mode:
        return resp
    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "type": "dict",
    "children": {
        "utf8_spam_tagging": {
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
            "name": "utf8-spam-tagging",
            "help": "Convert spam tags to UTF8 for better non-ascii character support.",
            "category": "unitary"
        },
        "ecmp_max_paths": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "ecmp-max-paths",
            "help": "Maximum number of ECMP next-hops.",
            "category": "unitary"
        },
        "sip_udp_port": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "sip-udp-port",
            "help": "UDP port the SIP proxy will monitor for SIP traffic.",
            "category": "unitary"
        },
        "ip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "ip",
            "help": "IP address and netmask.",
            "category": "unitary"
        },
        "per_ip_bandwidth": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "disable"
                },
                {
                    "value": "enable"
                }
            ],
            "name": "per-ip-bandwidth",
            "help": "Per-ip-bandwidth disable.",
            "category": "unitary"
        },
        "vpn_stats_log": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "ipsec"
                },
                {
                    "value": "pptp"
                },
                {
                    "value": "l2tp"
                },
                {
                    "value": "ssl"
                }
            ],
            "name": "vpn-stats-log",
            "help": "Enable periodic VPN log statistics.",
            "category": "unitary"
        },
        "bfd_detect_mult": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "bfd-detect-mult",
            "help": "BFD detection multiplier.",
            "category": "unitary"
        },
        "bfd_required_min_rx": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "bfd-required-min-rx",
            "help": "BFD required minimal rx interval.",
            "category": "unitary"
        },
        "wccp_cache_engine": {
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
            "name": "wccp-cache-engine",
            "help": "Enable wccp cache engine or not.",
            "category": "unitary"
        },
        "ip_ecmp_mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "source-ip-based"
                },
                {
                    "value": "dst-ip-based"
                },
                {
                    "value": "port-based"
                }
            ],
            "name": "ip-ecmp-mode",
            "help": "IP ecmp mode.",
            "category": "unitary"
        },
        "multicast_ttl_notchange": {
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
            "name": "multicast-ttl-notchange",
            "help": "Multicast ttl not change.",
            "category": "unitary"
        },
        "gateway": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "gateway",
            "help": "Default gateway ip address.",
            "category": "unitary"
        },
        "multicast_forward": {
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
            "name": "multicast-forward",
            "help": "Multicast forwarding.",
            "category": "unitary"
        },
        "bfd": {
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
            "name": "bfd",
            "help": "Enable Bidirectional Forwarding Detection (BFD) on all interfaces.",
            "category": "unitary"
        },
        "comments": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "comments",
            "help": "Vd comments.",
            "category": "unitary"
        },
        "vpn_stats_period": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "vpn-stats-period",
            "help": "Period to send VPN log statistics (seconds).",
            "category": "unitary"
        },
        "opmode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "nat"
                }
            ],
            "name": "opmode",
            "help": "Firewall operation mode.",
            "category": "unitary"
        },
        "bfd_desired_min_tx": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "bfd-desired-min-tx",
            "help": "BFD desired minimal tx interval.",
            "category": "unitary"
        },
        "sccp_port": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "sccp-port",
            "help": "TCP port the SCCP proxy will monitor for SCCP traffic.",
            "category": "unitary"
        },
        "asymroute6": {
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
            "name": "asymroute6",
            "help": "Asymmetric route6.",
            "category": "unitary"
        },
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
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "status",
            "help": "Enable/disable this VDOM.",
            "category": "unitary"
        },
        "asymroute": {
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
            "name": "asymroute",
            "help": "Asymmetric route.",
            "category": "unitary"
        },
        "allow_subnet_overlap": {
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
            "name": "allow-subnet-overlap",
            "help": "Allow one interface subnet overlap with other interfaces.",
            "category": "unitary"
        },
        "manageip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "manageip",
            "help": "IP address and netmask.",
            "category": "unitary"
        },
        "device": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "device",
            "help": "Interface.",
            "category": "unitary"
        },
        "sip_helper": {
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
            "name": "sip-helper",
            "help": "Helper to add dynamic sip firewall allow rule.",
            "category": "unitary"
        },
        "sip_tcp_port": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "sip-tcp-port",
            "help": "TCP port the SIP proxy will monitor for SIP traffic.",
            "category": "unitary"
        },
        "multicast_skip_policy": {
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
            "name": "multicast-skip-policy",
            "help": "Skip policy check,and allow multicast through.",
            "category": "unitary"
        },
        "sip_nat_trace": {
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
            "name": "sip-nat-trace",
            "help": "Add original IP if NATed.",
            "category": "unitary"
        },
        "bfd_dont_enforce_src_port": {
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
            "name": "bfd-dont-enforce-src-port",
            "help": "Verify Source Port of BFD Packets.",
            "category": "unitary"
        },
        "strict_src_check": {
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
            "name": "strict-src-check",
            "help": "Strict source verification.",
            "category": "unitary"
        }
    },
    "name": "settings",
    "help": "Settings.",
    "category": "complex"
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
        "system_settings": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_settings"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_settings"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_settings")
        is_error, has_changed, result, diff = fortiswitch_system(module.params, fos, module.check_mode)
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
