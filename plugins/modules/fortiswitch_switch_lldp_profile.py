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
module: fortiswitch_switch_lldp_profile
short_description: LLDP configuration profiles in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch_lldp feature and profile category.
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
    switch_lldp_profile:
        description:
            - LLDP configuration profiles.
        default: null
        type: dict
        suboptions:
            auto_isl:
                description:
                    - Enable/disable automatic inter-switch LAG.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auto_isl_auth:
                description:
                    - Automatic inter-switch LAG authentication.
                type: str
                choices:
                    - 'legacy'
                    - 'strict'
                    - 'relax'
            auto_isl_auth_encrypt:
                description:
                    - Automatic inter-switch LAG authentication encryption.
                type: str
                choices:
                    - 'none'
                    - 'must'
                    - 'mixed'
            auto_isl_auth_identity:
                description:
                    - Automatic authentication identity.
                type: str
            auto_isl_auth_macsec_profile:
                description:
                    - Fortilink LLDP macsec port profile.
                type: str
            auto_isl_auth_reauth:
                description:
                    - Automatic authentication reauth period (10 - 3600 mins).
                type: int
            auto_isl_auth_user:
                description:
                    - Automatic authentication User certificate.
                type: str
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
                    - 'enable'
                    - 'disable'
            custom_tlvs:
                description:
                    - Organizationally Specific TLV configuration.
                type: list
                elements: dict
                suboptions:
                    information_string:
                        description:
                            - Organizationally defined information string.
                        type: str
                    name:
                        description:
                            - TLV name (not sent).
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
                elements: dict
                suboptions:
                    name:
                        description:
                            - Policy type name.
                        type: str
                    status:
                        description:
                            - Enable/disable Location Service TLV.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    sys_location_id:
                        description:
                            - LLDP System Location Id.
                        type: str
            med_network_policy:
                description:
                    - LLDP MED network policy configuration.
                type: list
                elements: dict
                suboptions:
                    assign_vlan:
                        description:
                            - Enable/disable automatically adding this VLAN to ports with this profile (does not affect trunks).
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp:
                        description:
                            - Advertised DSCP value.
                        type: int
                    name:
                        description:
                            - Policy type name.
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
                            - 'disable'
                            - 'enable'
                    vlan:
                        description:
                            - VLAN to advertise (if configured on port).
                        type: int
            med_tlvs:
                description:
                    - Transmitted LLDP-MED TLVs.
                type: str
                choices:
                    - 'inventory-management'
                    - 'network-policy'
                    - 'location-identification'
                    - 'power-management'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            tlvs_802dot1:
                description:
                    - Transmitted IEEE 802.1 TLVs.
                type: str
                choices:
                    - 'port-vlan-id'
                    - 'vlan-name'
            tlvs_802dot3:
                description:
                    - Transmitted IEEE 802.3 TLVs.
                type: str
                choices:
                    - 'max-frame-size'
                    - 'power-negotiation'
                    - 'eee-config'
            vlan_name_map:
                description:
                    - VLANs that advertise Vlan Names
                type: str
'''

EXAMPLES = '''
- name: LLDP configuration profiles.
  fortinet.fortiswitch.fortiswitch_switch_lldp_profile:
      state: "present"
      switch_lldp_profile:
          802.1_tlvs: "port-vlan-id"
          802.3_tlvs: "max-frame-size"
          auto_isl: "enable"
          auto_isl_auth: "legacy"
          auto_isl_auth_encrypt: "none"
          auto_isl_auth_identity: "<your_own_value>"
          auto_isl_auth_macsec_profile: "<your_own_value> (source switch.macsec.profile.name)"
          auto_isl_auth_reauth: "10"
          auto_isl_auth_user: "<your_own_value> (source system.certificate.local.name)"
          auto_isl_hello_timer: "12"
          auto_isl_port_group: "13"
          auto_isl_receive_timeout: "14"
          auto_mclag_icl: "enable"
          custom_tlvs:
              -
                  information_string: "<your_own_value>"
                  name: "default_name_18"
                  oui: "<your_own_value>"
                  subtype: "20"
          med_location_service:
              -
                  name: "default_name_22"
                  status: "disable"
                  sys_location_id: "<your_own_value> (source system.location.name)"
          med_network_policy:
              -
                  assign_vlan: "disable"
                  dscp: "27"
                  name: "default_name_28"
                  priority: "29"
                  status: "disable"
                  vlan: "31"
          med_tlvs: "inventory-management"
          name: "default_name_33"
          vlan_name_map: "<your_own_value>"
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


def filter_switch_lldp_profile_data(json):
    option_list = ['802.1_tlvs', '802.3_tlvs', 'auto_isl',
                   'auto_isl_auth', 'auto_isl_auth_encrypt', 'auto_isl_auth_identity',
                   'auto_isl_auth_macsec_profile', 'auto_isl_auth_reauth', 'auto_isl_auth_user',
                   'auto_isl_hello_timer', 'auto_isl_port_group', 'auto_isl_receive_timeout',
                   'auto_mclag_icl', 'custom_tlvs', 'med_location_service',
                   'med_network_policy', 'med_tlvs', 'name',
                   'vlan_name_map']

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


def switch_lldp_profile(data, fos, check_mode=False):
    state = data['state']
    switch_lldp_profile_data = data['switch_lldp_profile']
    filtered_data = underscore_to_hyphen(filter_switch_lldp_profile_data(switch_lldp_profile_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('switch.lldp', 'profile', filtered_data)
        current_data = fos.get('switch.lldp', 'profile', mkey=mkey)
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


def fortiswitch_switch_lldp(data, fos, check_mode):
    fos.do_member_operation('switch.lldp', 'profile')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_lldp_profile']:
        resp = switch_lldp_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_lldp_profile'))
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
        "auto_mclag_icl": {
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
            "name": "auto-mclag-icl",
            "help": "Enable/disable MCLAG inter chassis link.",
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
            "help": "Profile name.",
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
            "help": "Enable/disable automatic inter-switch LAG.",
            "category": "unitary"
        },
        "tlvs_802dot3": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "max-frame-size"
                },
                {
                    "value": "power-negotiation"
                },
                {
                    "value": "eee-config"
                }
            ],
            "name": "802.3-tlvs",
            "help": "Transmitted IEEE 802.3 TLVs.",
            "category": "unitary"
        },
        "auto_isl_receive_timeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "auto-isl-receive-timeout",
            "help": "Automatic ISL timeout (0 - 300 sec).",
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
            "help": "Automatic inter-switch LAG port group.",
            "category": "unitary"
        },
        "custom_tlvs": {
            "type": "list",
            "elements": "dict",
            "children": {
                "subtype": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "subtype",
                    "help": "Organizationally defined subtype.",
                    "category": "unitary"
                },
                "oui": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "oui",
                    "help": "Organizationally unique identifier.",
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
                    "help": "TLV name (not sent).",
                    "category": "unitary"
                },
                "information_string": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "information-string",
                    "help": "Organizationally defined information string.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "custom-tlvs",
            "help": "Organizationally Specific TLV configuration.",
            "mkey": "name",
            "category": "table"
        },
        "med_location_service": {
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
                            "value": "disable"
                        },
                        {
                            "value": "enable"
                        }
                    ],
                    "name": "status",
                    "help": "Enable/disable Location Service TLV.",
                    "category": "unitary"
                },
                "sys_location_id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "sys-location-id",
                    "help": "LLDP System Location Id.",
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
                    "help": "Policy type name.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "med-location-service",
            "help": "LLDP MED location service configuration.",
            "mkey": "name",
            "category": "table"
        },
        "tlvs_802dot1": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "port-vlan-id"
                },
                {
                    "value": "vlan-name",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                }
            ],
            "name": "802.1-tlvs",
            "help": "Transmitted IEEE 802.1 TLVs.",
            "category": "unitary"
        },
        "med_tlvs": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "inventory-management"
                },
                {
                    "value": "network-policy"
                },
                {
                    "value": "location-identification"
                },
                {
                    "value": "power-management"
                }
            ],
            "name": "med-tlvs",
            "help": "Transmitted LLDP-MED TLVs.",
            "category": "unitary"
        },
        "med_network_policy": {
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
                            "value": "disable"
                        },
                        {
                            "value": "enable"
                        }
                    ],
                    "name": "status",
                    "help": "Enable/disable this TLV.",
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
                    "help": "Policy type name.",
                    "category": "unitary"
                },
                "vlan": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "vlan",
                    "help": "VLAN to advertise (if configured on port).",
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
                    "help": "Advertised DSCP value.",
                    "category": "unitary"
                },
                "priority": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "priority",
                    "help": "Advertised L2 priority.",
                    "category": "unitary"
                },
                "assign_vlan": {
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
                    "name": "assign-vlan",
                    "help": "Enable/disable automatically adding this VLAN to ports with this profile (does not affect trunks).",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "med-network-policy",
            "help": "LLDP MED network policy configuration.",
            "mkey": "name",
            "category": "table"
        },
        "auto_isl_hello_timer": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "auto-isl-hello-timer",
            "help": "Automatic ISL hello timer (1 - 30 sec).",
            "category": "unitary"
        },
        "vlan_name_map": {
            "v_range": [
                [
                    "v7.2.1",
                    ""
                ]
            ],
            "type": "string",
            "name": "vlan-name-map",
            "help": "VLANs that advertise Vlan Names",
            "category": "unitary"
        },
        "auto_isl_auth_encrypt": {
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
                    "value": "must",
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ]
                },
                {
                    "value": "mixed",
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ]
                }
            ],
            "name": "auto-isl-auth-encrypt",
            "help": "Automatic inter-switch LAG authentication encryption.",
            "category": "unitary"
        },
        "auto_isl_auth": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "legacy"
                },
                {
                    "value": "strict"
                },
                {
                    "value": "relax"
                }
            ],
            "name": "auto-isl-auth",
            "help": "Automatic inter-switch LAG authentication.",
            "category": "unitary"
        },
        "auto_isl_auth_user": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "auto-isl-auth-user",
            "help": "Automatic authentication User certificate.",
            "category": "unitary"
        },
        "auto_isl_auth_reauth": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "auto-isl-auth-reauth",
            "help": "Automatic authentication reauth period (10 - 3600 mins).",
            "category": "unitary"
        },
        "auto_isl_auth_identity": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "auto-isl-auth-identity",
            "help": "Automatic authentication identity.",
            "category": "unitary"
        },
        "auto_isl_auth_macsec_profile": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "auto-isl-auth-macsec-profile",
            "help": "Fortilink LLDP macsec port profile.",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "name": "profile",
    "help": "LLDP configuration profiles.",
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
        "switch_lldp_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_lldp_profile"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_lldp_profile"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_lldp_profile")
        is_error, has_changed, result, diff = fortiswitch_switch_lldp(module.params, fos, module.check_mode)
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
