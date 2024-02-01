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
module: fortiswitch_switch_global
short_description: Configure global settings in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch feature and global category.
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
    - ansible>=2.14
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

    switch_global:
        description:
            - Configure global settings.
        default: null
        type: dict
        suboptions:
            access_vlan_mode:
                description:
                    - Intra VLAN traffic behavior with loss of connection to the FortiGate.
                type: str
                choices:
                    - 'legacy'
                    - 'fail-open'
                    - 'fail-close'
            auto_fortilink_discovery:
                description:
                    - Enable/disable automatic FortiLink discovery.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auto_isl:
                description:
                    - Enable/Disable automatic inter switch LAG.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auto_isl_port_group:
                description:
                    - Configure global automatic inter-switch link port groups (overrides port level port groups).
                type: int
            auto_stp_priority:
                description:
                    - Automatic assignment of STP priority for tier1 and tier2 switches.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bpdu_learn:
                description:
                    - Enable/disable BPDU learn.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp_snooping_database_export:
                description:
                    - Enable/disable DHCP snoop database export to file.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dmi_global_all:
                description:
                    - Enable/disable DMI global status.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            flapguard_retain_trigger:
                description:
                    - Enable/disable retention of triggered state upon reboot.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            flood_unknown_multicast:
                description:
                    - Enable/disable unknown mcast flood in the vlan.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            flood_vtp:
                description:
                    - Enable/disable Cisco VTP flood in the vlan.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forti_trunk_dmac:
                description:
                    - Destination MAC address to be used for FortiTrunk heartbeat packets.
                type: str
            fortilink_heartbeat_timeout:
                description:
                    - Max fortilinkd echo replies that can be missed before fortilink is considered down.
                type: int
            fortilink_p2p_native_vlan:
                description:
                    - FortiLink point to point native VLAN.
                type: int
            fortilink_p2p_tpid:
                description:
                    - FortiLink point-to-point TPID.
                type: int
            fortilink_vlan_optimization:
                description:
                    - Controls VLAN assignment on ISL ports (assigns all 4k vlans when disabled).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ip_mac_binding:
                description:
                    - Configure ip-mac-binding status.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            l2_memory_check:
                description:
                    - Enable/disable L2 memory check, default interval is 120 seconds.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            l2_memory_check_interval:
                description:
                    - User defined interval to check L2 memory(second).
                type: int
            log_mac_limit_violations:
                description:
                    - Enable/disable logs for Learning Limit Violations globally.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            loop_guard_tx_interval:
                description:
                    - Loop guard packet Tx interval (sec).
                type: int
            mac_address:
                description:
                    - Manually configured MAC address when mac-address-algorithm is set to manual.
                type: int
            mac_address_algorithm:
                description:
                    - Method to configure the fifth byte of the MAC address
                type: str
                choices:
                    - 'auto'
                    - 'manual'
            mac_aging_interval:
                description:
                    - MAC address aging interval (sec; remove any MAC addresses unused since the the last check.
                type: int
            mac_violation_timer:
                description:
                    - Set a global timeout for Learning Limit Violations (0 = disabled).
                type: int
            max_path_in_ecmp_group:
                description:
                    - Set max path in one ecmp group.
                type: int
            mclag_igmpsnooping_aware:
                description:
                    - MCLAG IGMP-snooping aware.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mclag_peer_info_timeout:
                description:
                    - MCLAG peer info timeout.
                type: int
            mclag_port_base:
                description:
                    - MCLAG port base.
                type: int
            mclag_split_brain_all_ports_down:
                description:
                    - Enable/disable MCLAG split brain all ports down
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            mclag_split_brain_detect:
                description:
                    - Enable/disable MCLAG split brain detect.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mclag_split_brain_priority:
                description:
                    - Set MCLAG split brain priority
                type: int
            mclag_stp_aware:
                description:
                    - MCLAG STP aware.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mirror_qos:
                description:
                    - QOS value for locally mirrored traffic.
                type: int
            name:
                description:
                    - Name.
                type: str
            poe_alarm_threshold:
                description:
                    - Threshold (% of total power budget) above which an alarm event is generated.
                type: int
            poe_guard_band:
                description:
                    - Reserves power (W) in case of a spike in PoE consumption.
                type: int
            poe_power_budget:
                description:
                    - Set/override maximum power budget.
                type: int
            poe_power_mode:
                description:
                    - Set poe power mode to priority based or first come first served.
                type: str
                choices:
                    - 'priority'
                    - 'first-come-first-served'
            poe_pre_standard_detect:
                description:
                    - set poe-pre-standard-detect
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            port_security:
                description:
                    - Global parameters for port-security.
                type: dict
                suboptions:
                    link_down_auth:
                        description:
                            - If link down detected, "set-unauth" reverts to un-authorized state.
                        type: str
                        choices:
                            - 'set-unauth'
                            - 'no-action'
                    mab_entry_as:
                        description:
                            - Confgure MAB MAC entry as static or dynamic.
                        type: str
                        choices:
                            - 'static'
                            - 'dynamic'
                    mab_reauth:
                        description:
                            - Enable or disable MAB reauthentication settings.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    mac_called_station_delimiter:
                        description:
                            - MAC called station delimiter .
                        type: str
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac_calling_station_delimiter:
                        description:
                            - MAC calling station delimiter .
                        type: str
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac_case:
                        description:
                            - MAC case .
                        type: str
                        choices:
                            - 'uppercase'
                            - 'lowercase'
                    mac_password_delimiter:
                        description:
                            - MAC authentication password delimiter .
                        type: str
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac_username_delimiter:
                        description:
                            - MAC authentication username delimiter .
                        type: str
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    max_reauth_attempt:
                        description:
                            - 802.1X/MAB maximum reauthorization attempt.
                        type: int
                    quarantine_vlan:
                        description:
                            - Enable or disable Quarantine VLAN detection.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    reauth_period:
                        description:
                            - 802.1X/MAB reauthentication period ( minute ).
                        type: int
                    tx_period:
                        description:
                            - 802.1X tx period ( second ).
                        type: int
            trunk_hash_mode:
                description:
                    - Trunk hash mode.
                type: str
                choices:
                    - 'default'
                    - 'enhanced'
            trunk_hash_unicast_src_port:
                description:
                    - Enable/disable source port in Unicast trunk hashing.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trunk_hash_unkunicast_src_dst:
                description:
                    - Enable/disable trunk hash for unknown unicast src-dst.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            virtual_wire_tpid:
                description:
                    - TPID value used by virtual-wires.
                type: int
            vxlan_dport:
                description:
                    - VXLAN destination UDP port.
                type: int
            vxlan_port:
                description:
                    - VXLAN destination UDP port.
                type: int
            vxlan_sport:
                description:
                    - VXLAN source UDP port (0 - 65535).
                type: int
            vxlan_stp_virtual_mac:
                description:
                    - Virtual STP root MAC address
                type: str
            vxlan_stp_virtual_root:
                description:
                    - Enable/disable automatically making local switch the STP root for STP instances containing configured VXLAN"s access vlan.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
'''

EXAMPLES = '''
- name: Configure global settings.
  fortinet.fortiswitch.fortiswitch_switch_global:
      switch_global:
          access_vlan_mode: "legacy"
          auto_fortilink_discovery: "enable"
          auto_isl: "enable"
          auto_isl_port_group: "6"
          auto_stp_priority: "enable"
          bpdu_learn: "enable"
          dhcp_snooping_database_export: "enable"
          dmi_global_all: "enable"
          flapguard_retain_trigger: "enable"
          flood_unknown_multicast: "enable"
          flood_vtp: "enable"
          forti_trunk_dmac: "<your_own_value>"
          fortilink_heartbeat_timeout: "15"
          fortilink_p2p_native_vlan: "16"
          fortilink_p2p_tpid: "17"
          fortilink_vlan_optimization: "enable"
          ip_mac_binding: "enable"
          l2_memory_check: "enable"
          l2_memory_check_interval: "21"
          log_mac_limit_violations: "enable"
          loop_guard_tx_interval: "23"
          mac_address: "24"
          mac_address_algorithm: "auto"
          mac_aging_interval: "26"
          mac_violation_timer: "27"
          max_path_in_ecmp_group: "28"
          mclag_igmpsnooping_aware: "enable"
          mclag_peer_info_timeout: "30"
          mclag_port_base: "31"
          mclag_split_brain_all_ports_down: "disable"
          mclag_split_brain_detect: "enable"
          mclag_split_brain_priority: "34"
          mclag_stp_aware: "enable"
          mirror_qos: "36"
          name: "default_name_37"
          poe_alarm_threshold: "38"
          poe_guard_band: "39"
          poe_power_budget: "40"
          poe_power_mode: "priority"
          poe_pre_standard_detect: "enable"
          port_security:
              link_down_auth: "set-unauth"
              mab_entry_as: "static"
              mab_reauth: "disable"
              mac_called_station_delimiter: "hyphen"
              mac_calling_station_delimiter: "hyphen"
              mac_case: "uppercase"
              mac_password_delimiter: "hyphen"
              mac_username_delimiter: "hyphen"
              max_reauth_attempt: "52"
              quarantine_vlan: "disable"
              reauth_period: "54"
              tx_period: "55"
          trunk_hash_mode: "default"
          trunk_hash_unicast_src_port: "enable"
          trunk_hash_unkunicast_src_dst: "enable"
          virtual_wire_tpid: "59"
          vxlan_dport: "60"
          vxlan_port: "61"
          vxlan_sport: "62"
          vxlan_stp_virtual_mac: "<your_own_value>"
          vxlan_stp_virtual_root: "enable"
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


def filter_switch_global_data(json):
    option_list = ['access_vlan_mode', 'auto_fortilink_discovery', 'auto_isl',
                   'auto_isl_port_group', 'auto_stp_priority', 'bpdu_learn',
                   'dhcp_snooping_database_export', 'dmi_global_all', 'flapguard_retain_trigger',
                   'flood_unknown_multicast', 'flood_vtp', 'forti_trunk_dmac',
                   'fortilink_heartbeat_timeout', 'fortilink_p2p_native_vlan', 'fortilink_p2p_tpid',
                   'fortilink_vlan_optimization', 'ip_mac_binding', 'l2_memory_check',
                   'l2_memory_check_interval', 'log_mac_limit_violations', 'loop_guard_tx_interval',
                   'mac_address', 'mac_address_algorithm', 'mac_aging_interval',
                   'mac_violation_timer', 'max_path_in_ecmp_group', 'mclag_igmpsnooping_aware',
                   'mclag_peer_info_timeout', 'mclag_port_base', 'mclag_split_brain_all_ports_down',
                   'mclag_split_brain_detect', 'mclag_split_brain_priority', 'mclag_stp_aware',
                   'mirror_qos', 'name', 'poe_alarm_threshold',
                   'poe_guard_band', 'poe_power_budget', 'poe_power_mode',
                   'poe_pre_standard_detect', 'port_security', 'trunk_hash_mode',
                   'trunk_hash_unicast_src_port', 'trunk_hash_unkunicast_src_dst', 'virtual_wire_tpid',
                   'vxlan_dport', 'vxlan_port', 'vxlan_sport',
                   'vxlan_stp_virtual_mac', 'vxlan_stp_virtual_root']

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


def switch_global(data, fos):
    switch_global_data = data['switch_global']
    filtered_data = underscore_to_hyphen(filter_switch_global_data(switch_global_data))

    return fos.set('switch',
                   'global',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_switch(data, fos):
    fos.do_member_operation('switch', 'global')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_global']:
        resp = switch_global(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_global'))

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
        "fortilink_heartbeat_timeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "fortilink-heartbeat-timeout",
            "help": "Max fortilinkd echo replies that can be missed before fortilink is considered down.",
            "category": "unitary"
        },
        "log_mac_limit_violations": {
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
            "name": "log-mac-limit-violations",
            "help": "Enable/disable logs for Learning Limit Violations globally.",
            "category": "unitary"
        },
        "trunk_hash_unkunicast_src_dst": {
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
            "name": "trunk-hash-unkunicast-src-dst",
            "help": "Enable/disable trunk hash for unknown unicast src-dst.",
            "category": "unitary"
        },
        "poe_power_mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "priority"
                },
                {
                    "value": "first-come-first-served"
                }
            ],
            "name": "poe-power-mode",
            "help": "Set poe power mode to priority based or first come first served.",
            "category": "unitary"
        },
        "ip_mac_binding": {
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
            "name": "ip-mac-binding",
            "help": "Configure ip-mac-binding status.",
            "category": "unitary"
        },
        "mac_address_algorithm": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "auto"
                },
                {
                    "value": "manual"
                }
            ],
            "name": "mac-address-algorithm",
            "help": "Method to configure the fifth byte of the MAC address ",
            "category": "unitary"
        },
        "virtual_wire_tpid": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "virtual-wire-tpid",
            "help": "TPID value used by virtual-wires.",
            "category": "unitary"
        },
        "trunk_hash_unicast_src_port": {
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
            "name": "trunk-hash-unicast-src-port",
            "help": "Enable/disable source port in Unicast trunk hashing.",
            "category": "unitary"
        },
        "auto_fortilink_discovery": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.2.4"
                ],
                [
                    "v7.4.1",
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
            "name": "auto-fortilink-discovery",
            "help": "Enable/disable automatic FortiLink discovery.",
            "category": "unitary"
        },
        "max_path_in_ecmp_group": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "max-path-in-ecmp-group",
            "help": "Set max path in one ecmp group.",
            "category": "unitary"
        },
        "trunk_hash_mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "default"
                },
                {
                    "value": "enhanced"
                }
            ],
            "name": "trunk-hash-mode",
            "help": "Trunk hash mode.",
            "category": "unitary"
        },
        "fortilink_p2p_tpid": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "fortilink-p2p-tpid",
            "help": "FortiLink point-to-point TPID.",
            "category": "unitary"
        },
        "mac_violation_timer": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "mac-violation-timer",
            "help": "Set a global timeout for Learning Limit Violations (0 = disabled).",
            "category": "unitary"
        },
        "mirror_qos": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "mirror-qos",
            "help": "QOS value for locally mirrored traffic.",
            "category": "unitary"
        },
        "mclag_port_base": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "mclag-port-base",
            "help": "MCLAG port base.",
            "category": "unitary"
        },
        "flapguard_retain_trigger": {
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
            "name": "flapguard-retain-trigger",
            "help": "Enable/disable retention of triggered state upon reboot.",
            "category": "unitary"
        },
        "mac_address": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "mac-address",
            "help": "Manually configured MAC address when mac-address-algorithm is set to manual.",
            "category": "unitary"
        },
        "mclag_stp_aware": {
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
            "name": "mclag-stp-aware",
            "help": "MCLAG STP aware.",
            "category": "unitary"
        },
        "fortilink_p2p_native_vlan": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "fortilink-p2p-native-vlan",
            "help": "FortiLink point to point native VLAN.",
            "category": "unitary"
        },
        "fortilink_vlan_optimization": {
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
            "name": "fortilink-vlan-optimization",
            "help": "Controls VLAN assignment on ISL ports (assigns all 4k vlans when disabled).",
            "category": "unitary"
        },
        "loop_guard_tx_interval": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "loop-guard-tx-interval",
            "help": "Loop guard packet Tx interval (sec).",
            "category": "unitary"
        },
        "auto_isl_port_group": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "auto-isl-port-group",
            "help": "Configure global automatic inter-switch link port groups (overrides port level port groups).",
            "category": "unitary"
        },
        "poe_alarm_threshold": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "poe-alarm-threshold",
            "help": "Threshold (% of total power budget) above which an alarm event is generated.",
            "category": "unitary"
        },
        "poe_guard_band": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "poe-guard-band",
            "help": "Reserves power (W) in case of a spike in PoE consumption.",
            "category": "unitary"
        },
        "auto_stp_priority": {
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
            "name": "auto-stp-priority",
            "help": "Automatic assignment of STP priority for tier1 and tier2 switches.",
            "category": "unitary"
        },
        "poe_power_budget": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "poe-power-budget",
            "help": "Set/override maximum power budget.",
            "category": "unitary"
        },
        "mclag_peer_info_timeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "mclag-peer-info-timeout",
            "help": "MCLAG peer info timeout.",
            "category": "unitary"
        },
        "mclag_igmpsnooping_aware": {
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
            "name": "mclag-igmpsnooping-aware",
            "help": "MCLAG IGMP-snooping aware.",
            "category": "unitary"
        },
        "poe_pre_standard_detect": {
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
            "name": "poe-pre-standard-detect",
            "help": "set poe-pre-standard-detect",
            "category": "unitary"
        },
        "dhcp_snooping_database_export": {
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
            "name": "dhcp-snooping-database-export",
            "help": "Enable/disable DHCP snoop database export to file.",
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
            "help": "Name.",
            "category": "unitary"
        },
        "auto_isl": {
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
            "name": "auto-isl",
            "help": "Enable/Disable automatic inter switch LAG.",
            "category": "unitary"
        },
        "dmi_global_all": {
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
            "name": "dmi-global-all",
            "help": "Enable/disable DMI global status.",
            "category": "unitary"
        },
        "l2_memory_check": {
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
            "name": "l2-memory-check",
            "help": "Enable/disable L2 memory check,default interval is 120 seconds.",
            "category": "unitary"
        },
        "mclag_split_brain_detect": {
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
            "name": "mclag-split-brain-detect",
            "help": "Enable/disable MCLAG split brain detect.",
            "category": "unitary"
        },
        "forti_trunk_dmac": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "forti-trunk-dmac",
            "help": "Destination MAC address to be used for FortiTrunk heartbeat packets.",
            "category": "unitary"
        },
        "mac_aging_interval": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "mac-aging-interval",
            "help": "MAC address aging interval (sec; remove any MAC addresses unused since the the last check.",
            "category": "unitary"
        },
        "port_security": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "dict",
            "children": {
                "mab_reauth": {
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
                    "name": "mab-reauth",
                    "help": "Enable or disable MAB reauthentication settings.",
                    "category": "unitary"
                },
                "max_reauth_attempt": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "max-reauth-attempt",
                    "help": "802.1X/MAB maximum reauthorization attempt.",
                    "category": "unitary"
                },
                "link_down_auth": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "set-unauth"
                        },
                        {
                            "value": "no-action"
                        }
                    ],
                    "name": "link-down-auth",
                    "help": "If link down detected,'set-unauth' reverts to un-authorized state.",
                    "category": "unitary"
                },
                "reauth_period": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "reauth-period",
                    "help": "802.1X/MAB reauthentication period ( minute ).",
                    "category": "unitary"
                },
                "quarantine_vlan": {
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
                    "name": "quarantine-vlan",
                    "help": "Enable or disable Quarantine VLAN detection.",
                    "category": "unitary"
                },
                "tx_period": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "tx-period",
                    "help": "802.1X tx period ( second ).",
                    "category": "unitary"
                },
                "mac_called_station_delimiter": {
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "hyphen"
                        },
                        {
                            "value": "single-hyphen"
                        },
                        {
                            "value": "colon"
                        },
                        {
                            "value": "none"
                        }
                    ],
                    "name": "mac-called-station-delimiter",
                    "help": "MAC called station delimiter (default = hyphen).",
                    "category": "unitary"
                },
                "mac_case": {
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "uppercase"
                        },
                        {
                            "value": "lowercase"
                        }
                    ],
                    "name": "mac-case",
                    "help": "MAC case (default = lowercase).",
                    "category": "unitary"
                },
                "mac_password_delimiter": {
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "hyphen"
                        },
                        {
                            "value": "single-hyphen"
                        },
                        {
                            "value": "colon"
                        },
                        {
                            "value": "none"
                        }
                    ],
                    "name": "mac-password-delimiter",
                    "help": "MAC authentication password delimiter (default = hyphen).",
                    "category": "unitary"
                },
                "mab_entry_as": {
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "static"
                        },
                        {
                            "value": "dynamic"
                        }
                    ],
                    "name": "mab-entry-as",
                    "help": "Confgure MAB MAC entry as static or dynamic.",
                    "category": "unitary"
                },
                "mac_username_delimiter": {
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "hyphen"
                        },
                        {
                            "value": "single-hyphen"
                        },
                        {
                            "value": "colon"
                        },
                        {
                            "value": "none"
                        }
                    ],
                    "name": "mac-username-delimiter",
                    "help": "MAC authentication username delimiter (default = hyphen).",
                    "category": "unitary"
                },
                "mac_calling_station_delimiter": {
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "hyphen"
                        },
                        {
                            "value": "single-hyphen"
                        },
                        {
                            "value": "colon"
                        },
                        {
                            "value": "none"
                        }
                    ],
                    "name": "mac-calling-station-delimiter",
                    "help": "MAC calling station delimiter (default = hyphen).",
                    "category": "unitary"
                }
            },
            "name": "port-security",
            "help": "Global parameters for port-security.",
            "category": "complex"
        },
        "flood_unknown_multicast": {
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
            "name": "flood-unknown-multicast",
            "help": "Enable/disable unknown mcast flood in the vlan.",
            "category": "unitary"
        },
        "l2_memory_check_interval": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "l2-memory-check-interval",
            "help": "User defined interval to check L2 memory(second). ",
            "category": "unitary"
        },
        "mclag_split_brain_priority": {
            "v_range": [
                [
                    "v7.0.1",
                    ""
                ]
            ],
            "type": "integer",
            "name": "mclag-split-brain-priority",
            "help": "Set MCLAG split brain priority",
            "category": "unitary"
        },
        "mclag_split_brain_all_ports_down": {
            "v_range": [
                [
                    "v7.0.1",
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
            "name": "mclag-split-brain-all-ports-down",
            "help": "Enable/disable MCLAG split brain all ports down",
            "category": "unitary"
        },
        "bpdu_learn": {
            "v_range": [
                [
                    "v7.0.5",
                    "v7.0.6"
                ],
                [
                    "v7.2.2",
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
            "name": "bpdu-learn",
            "help": "Enable/disable BPDU learn.",
            "category": "unitary"
        },
        "flood_vtp": {
            "v_range": [
                [
                    "v7.0.5",
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
            "name": "flood-vtp",
            "help": "Enable/disable Cisco VTP flood in the vlan.",
            "category": "unitary"
        },
        "vxlan_stp_virtual_root": {
            "v_range": [
                [
                    "v7.2.1",
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
            "name": "vxlan-stp-virtual-root",
            "help": "Enable/disable automatically making local switch the STP root for STP instances containing configured VXLAN's access vlan.",
            "category": "unitary"
        },
        "vxlan_stp_virtual_mac": {
            "v_range": [
                [
                    "v7.2.1",
                    ""
                ]
            ],
            "type": "string",
            "name": "vxlan-stp-virtual-mac",
            "help": "Virtual STP root MAC address",
            "category": "unitary"
        },
        "vxlan_port": {
            "v_range": [
                [
                    "v7.2.1",
                    "v7.4.0"
                ]
            ],
            "type": "integer",
            "name": "vxlan-port",
            "help": "VXLAN destination UDP port.",
            "category": "unitary"
        },
        "vxlan_sport": {
            "v_range": [
                [
                    "v7.4.1",
                    ""
                ]
            ],
            "type": "integer",
            "name": "vxlan-sport",
            "help": "VXLAN source UDP port (0 - 65535).",
            "category": "unitary"
        },
        "access_vlan_mode": {
            "v_range": [
                [
                    "v7.4.1",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "legacy"
                },
                {
                    "value": "fail-open"
                },
                {
                    "value": "fail-close"
                }
            ],
            "name": "access-vlan-mode",
            "help": "Intra VLAN traffic behavior with loss of connection to the FortiGate.",
            "category": "unitary"
        },
        "vxlan_dport": {
            "v_range": [
                [
                    "v7.4.1",
                    ""
                ]
            ],
            "type": "integer",
            "name": "vxlan-dport",
            "help": "VXLAN destination UDP port.",
            "category": "unitary"
        }
    },
    "name": "global",
    "help": "Configure global settings.",
    "category": "complex"
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
        "switch_global": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_global"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_global"]['options'][attribute_name]['required'] = True

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_global")
        is_error, has_changed, result, diff = fortiswitch_switch(module.params, fos)
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
