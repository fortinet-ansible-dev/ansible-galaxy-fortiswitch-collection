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
module: fortiswitch_switch_physical_port
short_description: Physical port specific configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch feature and physical_port category.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    switch_physical_port:
        description:
            - Physical port specific configuration.
        default: null
        type: dict
        suboptions:
            cdp_status:
                description:
                    - CDP transmit and receive status (LLDP must be enabled in LLDP settings).
                type: str
                choices:
                    - 'disable'
                    - 'rx-only'
                    - 'tx-only'
                    - 'tx-rx'
            description:
                description:
                    - Description.
                type: str
            dmi_status:
                description:
                    - DMI status.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'global'
            eee_tx_idle_time:
                description:
                    - EEE Transmit idle time (microseconds)(0-2560).
                type: int
            eee_tx_wake_time:
                description:
                    - EEE Transmit wake time (microseconds)(0-2560).
                type: int
            egress_drop_mode:
                description:
                    - Enable/Disable egress drop.
                type: str
                choices:
                    - 'enabled'
                    - 'disabled'
            energy_efficient_ethernet:
                description:
                    - Enable / disable energy efficient ethernet.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            flap_duration:
                description:
                    - Period over which flap events are calculated (seconds).
                type: int
            flap_rate:
                description:
                    - Number of stage change events needed within flap-duration.
                type: int
            flap_timeout:
                description:
                    - Flap guard disabling protection (min).
                type: int
            flap_trig:
                description:
                    - Flag is set if triggered on this port.
                type: int
            flapguard:
                description:
                    - Enable / disable FlapGuard.
                type: str
                choices:
                    - 'enabled'
                    - 'disabled'
            flapguard_state:
                description:
                    - Timestamp of last triggered event (or 0 if none).
                type: str
            flow_control:
                description:
                    - Configure flow control pause frames.
                type: str
                choices:
                    - 'disable'
                    - 'tx'
                    - 'rx'
                    - 'both'
            fortilink_p2p:
                description:
                    - FortiLink point-to-point.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            l2_learning:
                description:
                    - Enable / disable dynamic MAC address learning.
                type: str
                choices:
                    - 'enabled'
                    - 'disabled'
            l2_sa_unknown:
                description:
                    - Forward / drop unknown(SMAC) packets when dynamic MAC address learning is disabled.
                type: str
                choices:
                    - 'forward'
                    - 'drop'
            link_status:
                description:
                    - Physical link status.
                type: str
            lldp_profile:
                description:
                    - LLDP port TLV profile.
                type: str
            lldp_status:
                description:
                    - LLDP transmit and receive status.
                type: str
                choices:
                    - 'disable'
                    - 'rx-only'
                    - 'tx-only'
                    - 'tx-rx'
            loopback:
                description:
                    - Phy Port Loopback.
                type: str
                choices:
                    - 'local'
                    - 'remote'
                    - 'disable'
            macsec_pae_mode:
                description:
                    - Assign PAE mode to a MACSEC interface.
                type: str
                choices:
                    - 'none'
                    - 'supp'
                    - 'auth'
            macsec_profile:
                description:
                    - macsec port profile.
                type: str
            max_frame_size:
                description:
                    - Maximum frame size.
                type: int
            medium:
                description:
                    - Configure port preference for shared ports.
                type: str
                choices:
                    - 'fiber-preferred'
                    - 'copper-preferred'
                    - 'fiber-forced'
                    - 'copper-forced'
            name:
                description:
                    - Port name.
                required: true
                type: str
            owning_interface:
                description:
                    - Trunk interface.
                type: str
            pause_meter_rate:
                description:
                    - Configure ingress metering rate. In kbits. 0 = disabled.
                type: int
            pause_resume:
                description:
                    - Resume threshold for resuming reception on pause metering of an ingress port.
                type: str
                choices:
                    - '75%'
                    - '50%'
                    - '25%'
            poe_port_mode:
                description:
                    - IEEE802.3AF/IEEE802.3AT
                type: str
                choices:
                    - 'IEEE802_3AF'
                    - 'IEEE802_3AT'
            poe_port_priority:
                description:
                    - Configure port priority
                type: str
                choices:
                    - 'low-priority'
                    - 'high-priority'
                    - 'critical-priority'
            poe_status:
                description:
                    - Enable/disable PSE.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            port_index:
                description:
                    - Port index.
                type: int
            priority_based_flow_control:
                description:
                    - Enable / disable priority-based flow control. 802.3 flow control will be applied when disabled
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            qsfp_low_power_mode:
                description:
                    - Enable/Disable QSFP low power mode.
                type: str
                choices:
                    - 'enabled'
                    - 'disabled'
            security_mode:
                description:
                    - Security mode.
                type: str
                choices:
                    - 'none'
                    - 'macsec'
            speed:
                description:
                    - Configure interface speed and duplex.
                type: str
                choices:
                    - 'auto'
                    - '10half'
                    - '10full'
                    - '100half'
                    - '100full'
                    - '100FX-half'
                    - '100FX-full'
                    - '1000full'
                    - '2500auto'
                    - '5000auto'
                    - '10000full'
                    - '10000cr'
                    - '10000sr'
                    - '40000full'
                    - '40000sr4'
                    - '40000cr4'
                    - '100000full'
                    - '100000cr4'
                    - '100000sr4'
                    - 'auto-module'
                    - '1000full-fiber'
                    - '1000auto'
                    - '25000full'
                    - '25000cr'
                    - '25000sr'
                    - '50000full'
                    - '50000cr'
                    - '50000sr'
                    - '2500full'
                    - '40000auto'
            status:
                description:
                    - Administrative status.
                type: str
                choices:
                    - 'up'
                    - 'down'
            storm_control:
                description:
                    - Storm control.
                type: dict
                suboptions:
                    broadcast:
                        description:
                            - Enable/disable broadcast storm control.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    burst_size_level:
                        description:
                            - Storm control burst size level 0-4.
                        type: int
                    rate:
                        description:
                            - Storm control traffic rate.
                        type: int
                    unknown_multicast:
                        description:
                            - Enable/disable unknown multicast storm control.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    unknown_unicast:
                        description:
                            - Enable/disable unknown unicast storm control.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            storm_control_mode:
                description:
                    - Storm control mode.
                type: str
                choices:
                    - 'global'
                    - 'override'
                    - 'disabled'
'''

EXAMPLES = '''
- name: Physical port specific configuration.
  fortinet.fortiswitch.fortiswitch_switch_physical_port:
      state: "present"
      switch_physical_port:
          cdp_status: "disable"
          description: "<your_own_value>"
          dmi_status: "enable"
          eee_tx_idle_time: "6"
          eee_tx_wake_time: "7"
          egress_drop_mode: "enabled"
          energy_efficient_ethernet: "enable"
          flap_duration: "10"
          flap_rate: "11"
          flap_timeout: "12"
          flap_trig: "13"
          flapguard: "enabled"
          flapguard_state: "<your_own_value>"
          flow_control: "disable"
          fortilink_p2p: "enable"
          l2_learning: "enabled"
          l2_sa_unknown: "forward"
          link_status: "<your_own_value>"
          lldp_profile: "<your_own_value> (source switch.lldp.profile.name)"
          lldp_status: "disable"
          loopback: "local"
          macsec_pae_mode: "none"
          macsec_profile: "<your_own_value> (source switch.macsec.profile.name)"
          max_frame_size: "26"
          medium: "fiber-preferred"
          name: "default_name_28"
          owning_interface: "<your_own_value>"
          pause_meter_rate: "30"
          pause_resume: "75%"
          poe_port_mode: "IEEE802_3AF"
          poe_port_priority: "low-priority"
          poe_status: "enable"
          port_index: "35"
          priority_based_flow_control: "disable"
          qsfp_low_power_mode: "enabled"
          security_mode: "none"
          speed: "auto"
          status: "up"
          storm_control:
              broadcast: "enable"
              burst_size_level: "43"
              rate: "44"
              unknown_multicast: "enable"
              unknown_unicast: "enable"
          storm_control_mode: "global"
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


def filter_switch_physical_port_data(json):
    option_list = ['cdp_status', 'description', 'dmi_status',
                   'eee_tx_idle_time', 'eee_tx_wake_time', 'egress_drop_mode',
                   'energy_efficient_ethernet', 'flap_duration', 'flap_rate',
                   'flap_timeout', 'flap_trig', 'flapguard',
                   'flapguard_state', 'flow_control', 'fortilink_p2p',
                   'l2_learning', 'l2_sa_unknown', 'link_status',
                   'lldp_profile', 'lldp_status', 'loopback',
                   'macsec_pae_mode', 'macsec_profile', 'max_frame_size',
                   'medium', 'name', 'owning_interface',
                   'pause_meter_rate', 'pause_resume', 'poe_port_mode',
                   'poe_port_priority', 'poe_status', 'port_index',
                   'priority_based_flow_control', 'qsfp_low_power_mode', 'security_mode',
                   'speed', 'status', 'storm_control',
                   'storm_control_mode']

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


def switch_physical_port(data, fos, check_mode=False):
    state = data['state']
    switch_physical_port_data = data['switch_physical_port']
    filtered_data = underscore_to_hyphen(filter_switch_physical_port_data(switch_physical_port_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('switch', 'physical-port', filtered_data)
        current_data = fos.get('switch', 'physical-port', mkey=mkey)
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
        return fos.set('switch',
                       'physical-port',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('switch',
                          'physical-port',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_switch(data, fos, check_mode):
    fos.do_member_operation('switch', 'physical-port')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_physical_port']:
        resp = switch_physical_port(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_physical_port'))
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
        "l2_learning": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enabled"
                },
                {
                    "value": "disabled"
                }
            ],
            "name": "l2-learning",
            "help": "Enable / disable dynamic MAC address learning.",
            "category": "unitary"
        },
        "dmi_status": {
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
                },
                {
                    "value": "global"
                }
            ],
            "name": "dmi-status",
            "help": "DMI status.",
            "category": "unitary"
        },
        "storm_control_mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "global"
                },
                {
                    "value": "override"
                },
                {
                    "value": "disabled"
                }
            ],
            "name": "storm-control-mode",
            "help": "Storm control mode.",
            "category": "unitary"
        },
        "speed": {
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
                    "value": "10half"
                },
                {
                    "value": "10full"
                },
                {
                    "value": "100half"
                },
                {
                    "value": "100full"
                },
                {
                    "value": "100FX-half"
                },
                {
                    "value": "100FX-full"
                },
                {
                    "value": "1000full"
                },
                {
                    "value": "2500auto"
                },
                {
                    "value": "5000auto"
                },
                {
                    "value": "10000full"
                },
                {
                    "value": "10000cr"
                },
                {
                    "value": "10000sr"
                },
                {
                    "value": "40000full"
                },
                {
                    "value": "40000sr4"
                },
                {
                    "value": "40000cr4"
                },
                {
                    "value": "100000full"
                },
                {
                    "value": "100000cr4"
                },
                {
                    "value": "100000sr4"
                },
                {
                    "value": "auto-module"
                },
                {
                    "value": "1000full-fiber"
                },
                {
                    "value": "1000auto"
                },
                {
                    "value": "25000full"
                },
                {
                    "value": "25000cr"
                },
                {
                    "value": "25000sr"
                },
                {
                    "value": "50000full"
                },
                {
                    "value": "50000cr"
                },
                {
                    "value": "50000sr"
                },
                {
                    "value": "2500full",
                    "v_range": [
                        [
                            "v7.4.0",
                            ""
                        ]
                    ]
                },
                {
                    "value": "40000auto",
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ]
                }
            ],
            "name": "speed",
            "help": "Configure interface speed and duplex.",
            "category": "unitary"
        },
        "fortilink_p2p": {
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
            "name": "fortilink-p2p",
            "help": "FortiLink point-to-point.",
            "category": "unitary"
        },
        "flap_rate": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "flap-rate",
            "help": "Number of stage change events needed within flap-duration.",
            "category": "unitary"
        },
        "egress_drop_mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enabled"
                },
                {
                    "value": "disabled"
                }
            ],
            "name": "egress-drop-mode",
            "help": "Enable/Disable egress drop.",
            "category": "unitary"
        },
        "loopback": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "local"
                },
                {
                    "value": "remote"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "loopback",
            "help": "Phy Port Loopback.",
            "category": "unitary"
        },
        "priority_based_flow_control": {
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
            "name": "priority-based-flow-control",
            "help": "Enable / disable priority-based flow control. 802.3 flow control will be applied when disabled",
            "category": "unitary"
        },
        "owning_interface": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "owning-interface",
            "help": "Trunk interface.",
            "category": "unitary"
        },
        "energy_efficient_ethernet": {
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
            "name": "energy-efficient-ethernet",
            "help": "Enable / disable energy efficient ethernet.",
            "category": "unitary"
        },
        "qsfp_low_power_mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enabled"
                },
                {
                    "value": "disabled"
                }
            ],
            "name": "qsfp-low-power-mode",
            "help": "Enable/Disable QSFP low power mode.",
            "category": "unitary"
        },
        "poe_status": {
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
            "name": "poe-status",
            "help": "Enable/disable PSE.",
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
                    "value": "up"
                },
                {
                    "value": "down"
                }
            ],
            "name": "status",
            "help": "Administrative status.",
            "category": "unitary"
        },
        "medium": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "fiber-preferred"
                },
                {
                    "value": "copper-preferred"
                },
                {
                    "value": "fiber-forced"
                },
                {
                    "value": "copper-forced"
                }
            ],
            "name": "medium",
            "help": "Configure port preference for shared ports.",
            "category": "unitary"
        },
        "cdp_status": {
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
                    "value": "rx-only"
                },
                {
                    "value": "tx-only"
                },
                {
                    "value": "tx-rx"
                }
            ],
            "name": "cdp-status",
            "help": "CDP transmit and receive status (LLDP must be enabled in LLDP settings).",
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
            "help": "Description.",
            "category": "unitary"
        },
        "flapguard": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enabled"
                },
                {
                    "value": "disabled"
                }
            ],
            "name": "flapguard",
            "help": "Enable / disable FlapGuard.",
            "category": "unitary"
        },
        "flap_duration": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "flap-duration",
            "help": "Period over which flap events are calculated (seconds).",
            "category": "unitary"
        },
        "eee_tx_wake_time": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "eee-tx-wake-time",
            "help": "EEE Transmit wake time (microseconds)(0-2560).",
            "category": "unitary"
        },
        "storm_control": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "dict",
            "children": {
                "broadcast": {
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
                    "name": "broadcast",
                    "help": "Enable/disable broadcast storm control.",
                    "category": "unitary"
                },
                "unknown_unicast": {
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
                    "name": "unknown-unicast",
                    "help": "Enable/disable unknown unicast storm control.",
                    "category": "unitary"
                },
                "unknown_multicast": {
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
                    "name": "unknown-multicast",
                    "help": "Enable/disable unknown multicast storm control.",
                    "category": "unitary"
                },
                "rate": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "rate",
                    "help": "Storm control traffic rate.",
                    "category": "unitary"
                },
                "burst_size_level": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "burst-size-level",
                    "help": "Storm control burst size level 0-4.",
                    "category": "unitary"
                }
            },
            "name": "storm-control",
            "help": "Storm control.",
            "category": "complex"
        },
        "flapguard_state": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "flapguard-state",
            "help": "Timestamp of last triggered event (or 0 if none).",
            "category": "unitary"
        },
        "pause_resume": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "75%"
                },
                {
                    "value": "50%"
                },
                {
                    "value": "25%"
                }
            ],
            "name": "pause-resume",
            "help": "Resume threshold for resuming reception on pause metering of an ingress port.",
            "category": "unitary"
        },
        "l2_sa_unknown": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "forward"
                },
                {
                    "value": "drop"
                }
            ],
            "name": "l2-sa-unknown",
            "help": "Forward / drop unknown(SMAC) packets when dynamic MAC address learning is disabled.",
            "category": "unitary"
        },
        "lldp_status": {
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
                    "value": "rx-only"
                },
                {
                    "value": "tx-only"
                },
                {
                    "value": "tx-rx"
                }
            ],
            "name": "lldp-status",
            "help": "LLDP transmit and receive status.",
            "category": "unitary"
        },
        "eee_tx_idle_time": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "eee-tx-idle-time",
            "help": "EEE Transmit idle time (microseconds)(0-2560).",
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
            "help": "Port name.",
            "category": "unitary"
        },
        "lldp_profile": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "lldp-profile",
            "help": "LLDP port TLV profile.",
            "category": "unitary"
        },
        "flap_trig": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.4.1"
                ]
            ],
            "type": "integer",
            "name": "flap-trig",
            "help": "Flag is set if triggered on this port.",
            "category": "unitary"
        },
        "link_status": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "link-status",
            "help": "Physical link status.",
            "category": "unitary"
        },
        "flap_timeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "flap-timeout",
            "help": "Flap guard disabling protection (min).",
            "category": "unitary"
        },
        "poe_port_mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "IEEE802_3AF"
                },
                {
                    "value": "IEEE802_3AT"
                }
            ],
            "name": "poe-port-mode",
            "help": "IEEE802.3AF/IEEE802.3AT",
            "category": "unitary"
        },
        "port_index": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "port-index",
            "help": "Port index.",
            "category": "unitary"
        },
        "max_frame_size": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "max-frame-size",
            "help": "Maximum frame size.",
            "category": "unitary"
        },
        "flow_control": {
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
                    "value": "tx"
                },
                {
                    "value": "rx"
                },
                {
                    "value": "both"
                }
            ],
            "name": "flow-control",
            "help": "Configure flow control pause frames.",
            "category": "unitary"
        },
        "pause_meter_rate": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "pause-meter-rate",
            "help": "Configure ingress metering rate. In kbits. 0 = disabled.",
            "category": "unitary"
        },
        "poe_port_priority": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "low-priority"
                },
                {
                    "value": "high-priority"
                },
                {
                    "value": "critical-priority"
                }
            ],
            "name": "poe-port-priority",
            "help": "Configure port priority",
            "category": "unitary"
        },
        "macsec_pae_mode": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "supp"
                },
                {
                    "value": "auth"
                }
            ],
            "name": "macsec-pae-mode",
            "help": "Assign PAE mode to a MACSEC interface.",
            "category": "unitary"
        },
        "macsec_profile": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "macsec-profile",
            "help": "macsec port profile.",
            "category": "unitary"
        },
        "security_mode": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "none"
                },
                {
                    "value": "macsec"
                }
            ],
            "name": "security-mode",
            "help": "Security mode.",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "name": "physical-port",
    "help": "Physical port specific configuration.",
    "mkey": "name",
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
        "switch_physical_port": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_physical_port"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_physical_port"]['options'][attribute_name]['required'] = True

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
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_physical_port")
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
