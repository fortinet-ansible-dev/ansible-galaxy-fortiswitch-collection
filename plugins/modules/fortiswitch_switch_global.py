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
module: fortiswitch_switch_global
short_description: Configure global settings in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch feature and global category.
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
    
    switch_global:
        description:
            - Configure global settings.
        default: null
        type: dict
        suboptions:
            auto_fortilink_discovery:
                description:
                    - Enable/disable automatic FortiLink discovery.
                type: str
                choices:
                    - enable
                    - disable
            auto_isl:
                description:
                    - Enable/Disable automatic inter switch LAG.
                type: str
                choices:
                    - enable
                    - disable
            auto_isl_port_group:
                description:
                    - Configure global automatic inter-switch link port groups (overrides port level port groups).
                type: int
            auto_stp_priority:
                description:
                    - Automatic assignment of STP priority for tier1 and tier2 switches.
                type: str
                choices:
                    - enable
                    - disable
            dhcp_snooping_database_export:
                description:
                    - Enable/disable DHCP snoop database export to file.
                type: str
                choices:
                    - enable
                    - disable
            dmi_global_all:
                description:
                    - Enable/disable DMI global status.
                type: str
                choices:
                    - enable
                    - disable
            flapguard_retain_trigger:
                description:
                    - Enable/disable retention of triggered state upon reboot.
                type: str
                choices:
                    - enable
                    - disable
            flood_unknown_multicast:
                description:
                    - Enable/disable unknown mcast flood in the vlan.
                type: str
                choices:
                    - enable
                    - disable
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
                    - enable
                    - disable
            ip_mac_binding:
                description:
                    - Configure ip-mac-binding status.
                type: str
                choices:
                    - enable
                    - disable
            l2_memory_check:
                description:
                    - Enable/disable L2 memory check, default interval is 120 seconds.
                type: str
                choices:
                    - enable
                    - disable
            l2_memory_check_interval:
                description:
                    - User defined interval to check L2 memory(second). 
                type: int
            log_mac_limit_violations:
                description:
                    - Enable/disable logs for Learning Limit Violations globally.
                type: str
                choices:
                    - enable
                    - disable
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
                    - 'Method to configure the fifth byte of the MAC address (12:34:56:78:XX:XX, sixth byte automatically generated from managmenet MAC,
                       channel, and port information).'
                type: str
                choices:
                    - auto
                    - manual
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
                    - enable
                    - disable
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
                    - disable
                    - enable
            mclag_split_brain_detect:
                description:
                    - Enable/disable MCLAG split brain detect.
                type: str
                choices:
                    - enable
                    - disable
            mclag_split_brain_priority:
                description:
                    - Set MCLAG split brain priority
                type: int
            mclag_stp_aware:
                description:
                    - MCLAG STP aware.
                type: str
                choices:
                    - enable
                    - disable
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
                    - priority
                    - first-come-first-served
            poe_pre_standard_detect:
                description:
                    - set poe-pre-standard-detect
                type: str
                choices:
                    - enable
                    - disable
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
                            - set-unauth
                            - no-action
                    mab_reauth:
                        description:
                            - Enable or disable MAB reauthentication settings.
                        type: str
                        choices:
                            - disable
                            - enable
                    max_reauth_attempt:
                        description:
                            - 802.1X/MAB maximum reauthorization attempt.
                        type: int
                    quarantine_vlan:
                        description:
                            - Enable or disable Quarantine VLAN detection.
                        type: str
                        choices:
                            - disable
                            - enable
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
                    - default
                    - enhanced
            trunk_hash_unicast_src_port:
                description:
                    - Enable/disable source port in Unicast trunk hashing.
                type: str
                choices:
                    - enable
                    - disable
            trunk_hash_unkunicast_src_dst:
                description:
                    - Enable/disable trunk hash for unknown unicast src-dst.
                type: str
                choices:
                    - enable
                    - disable
            virtual_wire_tpid:
                description:
                    - TPID value used by virtual-wires.
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
  - name: Configure global settings.
    fortiswitch_switch_global:
      state: "present"
      switch_global:
        auto_fortilink_discovery: "enable"
        auto_isl: "enable"
        auto_isl_port_group: "5"
        auto_stp_priority: "enable"
        dhcp_snooping_database_export: "enable"
        dmi_global_all: "enable"
        flapguard_retain_trigger: "enable"
        flood_unknown_multicast: "enable"
        forti_trunk_dmac: "<your_own_value>"
        fortilink_heartbeat_timeout: "12"
        fortilink_p2p_native_vlan: "13"
        fortilink_p2p_tpid: "14"
        fortilink_vlan_optimization: "enable"
        ip_mac_binding: "enable"
        l2_memory_check: "enable"
        l2_memory_check_interval: "18"
        log_mac_limit_violations: "enable"
        loop_guard_tx_interval: "20"
        mac_address: "21"
        mac_address_algorithm: "auto"
        mac_aging_interval: "23"
        mac_violation_timer: "24"
        max_path_in_ecmp_group: "25"
        mclag_igmpsnooping_aware: "enable"
        mclag_peer_info_timeout: "27"
        mclag_port_base: "28"
        mclag_split_brain_all_ports_down: "disable"
        mclag_split_brain_detect: "enable"
        mclag_split_brain_priority: "31"
        mclag_stp_aware: "enable"
        mirror_qos: "33"
        name: "default_name_34"
        poe_alarm_threshold: "35"
        poe_guard_band: "36"
        poe_power_budget: "37"
        poe_power_mode: "priority"
        poe_pre_standard_detect: "enable"
        port_security:
            link_down_auth: "set-unauth"
            mab_reauth: "disable"
            max_reauth_attempt: "43"
            quarantine_vlan: "disable"
            reauth_period: "45"
            tx_period: "46"
        trunk_hash_mode: "default"
        trunk_hash_unicast_src_port: "enable"
        trunk_hash_unkunicast_src_dst: "enable"
        virtual_wire_tpid: "50"

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
def filter_switch_global_data(json):
    option_list = ['auto_fortilink_discovery', 'auto_isl', 'auto_isl_port_group',
                   'auto_stp_priority', 'dhcp_snooping_database_export', 'dmi_global_all',
                   'flapguard_retain_trigger', 'flood_unknown_multicast', 'forti_trunk_dmac',
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
                   'trunk_hash_unicast_src_port', 'trunk_hash_unkunicast_src_dst', 'virtual_wire_tpid' ]
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

    fos.do_member_operation('switch_global')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_global']:
        resp = switch_global(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_global'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp



versioned_schema = {
    "type": "dict", 
    "children": {
        "forti_trunk_dmac": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "poe_power_budget": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "trunk_hash_unicast_src_port": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "mclag_stp_aware": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "l2_memory_check_interval": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "mclag_port_base": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "mclag_split_brain_detect": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "auto_fortilink_discovery": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "mac_violation_timer": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "ip_mac_binding": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "flood_unknown_multicast": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "max_path_in_ecmp_group": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "fortilink_heartbeat_timeout": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "fortilink_p2p_native_vlan": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "mclag_peer_info_timeout": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "mirror_qos": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "dmi_global_all": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "poe_pre_standard_detect": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "mac_aging_interval": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "log_mac_limit_violations": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "mac_address_algorithm": {
            "type": "string", 
            "options": [
                {
                    "value": "auto", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "manual", 
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
        "trunk_hash_unkunicast_src_dst": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "trunk_hash_mode": {
            "type": "string", 
            "options": [
                {
                    "value": "default", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "enhanced", 
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
        "loop_guard_tx_interval": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "mclag_igmpsnooping_aware": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "flapguard_retain_trigger": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "l2_memory_check": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "mac_address": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "mclag_split_brain_all_ports_down": {
            "type": "string", 
            "options": [
                {
                    "value": "disable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True
                    }
                }, 
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True
                    }
                }
            ], 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True
            }
        }, 
        "poe_alarm_threshold": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "poe_guard_band": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "port_security": {
            "type": "dict", 
            "children": {
                "reauth_period": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "max_reauth_attempt": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "link_down_auth": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "set-unauth", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "no-action", 
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
                "quarantine_vlan": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "disable", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "enable", 
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
                "mab_reauth": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "disable", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "enable", 
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
                "tx_period": {
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
        "auto_isl_port_group": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "dhcp_snooping_database_export": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "virtual_wire_tpid": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "fortilink_vlan_optimization": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "name": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "auto_stp_priority": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "poe_power_mode": {
            "type": "string", 
            "options": [
                {
                    "value": "priority", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "first-come-first-served", 
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
        "auto_isl": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "mclag_split_brain_priority": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True
            }
        }, 
        "fortilink_p2p_tpid": {
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
        "switch_global": {
            "required": False, "type": "dict", "default": None,
            "options": { 
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_global"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_global"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_global")
        
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