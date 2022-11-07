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
module: fortiswitch_switch_vlan
short_description: Configure optional per-VLAN settings in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch feature and vlan category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v7.0.0
version_added: "1.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
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
    switch_vlan:
        description:
            - Configure optional per-VLAN settings.
        default: null
        type: dict
        suboptions:
            access_vlan:
                description:
                    - Block port-to-port traffic.
                type: str
                choices:
                    - disable
                    - enable
            arp_inspection:
                description:
                    - Enable/Disable Dynamic ARP Inspection.
                type: str
                choices:
                    - disable
                    - enable
            community_vlans:
                description:
                    - Communities within this private VLAN.
                type: str
            cos_queue:
                description:
                    - Set cos(0-7) on the VLAN traffic or unset to disable.
                type: int
            description:
                description:
                    - Description.
                type: str
            dhcp_server_access_list:
                description:
                    - Configure dhcp server access list.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User given name for dhcp-server.
                        type: str
                    server_ip:
                        description:
                            - IP address for DHCP Server.
                        type: str
                    server_ip6:
                        description:
                            - IP address for DHCPv6 Server.
                        type: str
            dhcp_snooping:
                description:
                    - Enable/Disable dhcp snooping on this vlan.
                type: str
                choices:
                    - disable
                    - enable
            dhcp_snooping_option82:
                description:
                    - Enable/Disable inserting option82.
                type: str
                choices:
                    - disable
                    - enable
            dhcp_snooping_verify_mac:
                description:
                    - Enable/Disable verify source mac.
                type: str
                choices:
                    - disable
                    - enable
            dhcp6_snooping:
                description:
                    - Enable/Disable DHCPv6 snooping on this vlan.
                type: str
                choices:
                    - disable
                    - enable
            id:
                description:
                    - VLAN ID.
                required: true
                type: int
            igmp_snooping:
                description:
                    - Enable/disable IGMP-snooping for the VLAN interface.
                type: str
                choices:
                    - enable
                    - disable
            igmp_snooping_fast_leave:
                description:
                    - Enable/disable IGMP snooping fast leave.
                type: str
                choices:
                    - enable
                    - disable
            igmp_snooping_proxy:
                description:
                    - Enable/disable IGMP snooping proxy for the VLAN interface.
                type: str
                choices:
                    - enable
                    - disable
            igmp_snooping_querier:
                description:
                    - Enable/disable IGMP-snooping-querier for the VLAN interface.
                type: str
                choices:
                    - enable
                    - disable
            igmp_snooping_querier_addr:
                description:
                    - IGMP-snooping-querier address.
                type: str
            igmp_snooping_querier_version:
                description:
                    - IGMP-snooping-querier version.
                type: int
            igmp_snooping_static_group:
                description:
                    - IGMP static groups.
                type: list
                elements: dict
                suboptions:
                    mcast_addr:
                        description:
                            - Multicast address for static-group.
                        type: str
                    members:
                        description:
                            - Member interfaces.
                        type: list
                        elements: dict
                        suboptions:
                            member_name:
                                description:
                                    - Interface name. Source switch.interface.name.
                                type: str
                    name:
                        description:
                            - Group name.
                        type: str
            isolated_vlan:
                description:
                    - Isolated VLAN.
                type: int
            lan_segment:
                description:
                    - Enable/disable LAN Segment.
                type: str
                choices:
                    - enable
                    - disable
            lan_segment_primary_vlan:
                description:
                    - LAN Segment Primary VLAN ID.
                type: int
            lan_segment_type:
                description:
                    - LAN segment type.
                type: int
            lan_subvlans:
                description:
                    - LAN segment subvlans.
                type: str
            learning:
                description:
                    - Enable/disable L2 learning on this VLAN.
                type: str
                choices:
                    - disable
                    - enable
            learning_limit:
                description:
                    - Limit the number of dynamic MAC addresses on this VLAN.
                type: int
            member_by_ipv4:
                description:
                    - Assign VLAN membership based on IPv4 address or subnet.
                type: list
                elements: dict
                suboptions:
                    address:
                        description:
                            - Address(/32) or subnet.
                        type: str
                    description:
                        description:
                            - Description.
                        type: str
                    id:
                        description:
                            - Entry ID.
                        type: int
            member_by_ipv6:
                description:
                    - Assign VLAN membership based on IPv6 prefix.
                type: list
                elements: dict
                suboptions:
                    description:
                        description:
                            - Description.
                        type: str
                    id:
                        description:
                            - Entry ID.
                        type: int
                    prefix:
                        description:
                            - IPv6 prefix (max = /64).
                        type: str
            member_by_mac:
                description:
                    - Assign VLAN membership based on MAC address.
                type: list
                elements: dict
                suboptions:
                    description:
                        description:
                            - Description.
                        type: str
                    id:
                        description:
                            - Entry ID.
                        type: int
                    mac:
                        description:
                            - MAC address.
                        type: str
            member_by_proto:
                description:
                    - Assign VLAN membership based on ethernet frametype and protocol.
                type: list
                elements: dict
                suboptions:
                    description:
                        description:
                            - Description.
                        type: str
                    frametypes:
                        description:
                            - Ethernet frame types to check.
                        type: str
                        choices:
                            - ethernet2
                            - 802.3d
                            - llc
                    id:
                        description:
                            - Entry ID.
                        type: int
                    protocol:
                        description:
                            - Ethernet protocols (0 - 65535).
                        type: int
            mld_snooping:
                description:
                    - Enable/disable MLD snooping for the VLAN interface.
                type: str
                choices:
                    - enable
                    - disable
            mld_snooping_fast_leave:
                description:
                    - Enable/disable MLD snooping fast leave.
                type: str
                choices:
                    - enable
                    - disable
            mld_snooping_proxy:
                description:
                    - Enable/disable MLD snooping proxy for the VLAN interface.
                type: str
                choices:
                    - enable
                    - disable
            mld_snooping_querier:
                description:
                    - Enable/disable MLD snooping querier for the VLAN interface.
                type: str
                choices:
                    - enable
                    - disable
            mld_snooping_querier_addr:
                description:
                    - MLD-querier address.
                type: str
            mld_snooping_static_group:
                description:
                    - MLD static groups.
                type: list
                elements: dict
                suboptions:
                    mcast_addr:
                        description:
                            - IPv6 Multicast address for static-group.
                        type: str
                    members:
                        description:
                            - Member interfaces.
                        type: list
                        elements: dict
                        suboptions:
                            member_name:
                                description:
                                    - Interface name. Source switch.interface.name.
                                type: str
                    name:
                        description:
                            - Group name.
                        type: str
            mrouter_ports:
                description:
                    - Member interfaces.
                type: list
                elements: dict
                suboptions:
                    member_name:
                        description:
                            - Interface name.
                        type: str
            policer:
                description:
                    - Set policer on the VLAN traffic. Source switch.acl.policer.id.
                type: int
            primary_vlan:
                description:
                    - Primary VLAN ID.
                type: int
            private_vlan:
                description:
                    - Enable/disable private VLAN.
                type: str
                choices:
                    - enable
                    - disable
            private_vlan_type:
                description:
                    - Private VLAN type.
                type: int
            rspan_mode:
                description:
                    - Stop L2 learning and interception of BPDUs and other packets on this VLAN.
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
  - name: Configure optional per-VLAN settings.
    fortiswitch_switch_vlan:
      state: "present"
      switch_vlan:
        access_vlan: "disable"
        arp_inspection: "disable"
        community_vlans: "<your_own_value>"
        cos_queue: "6"
        description: "<your_own_value>"
        dhcp_server_access_list:
         -
            name: "default_name_9"
            server_ip: "<your_own_value>"
            server_ip6: "<your_own_value>"
        dhcp_snooping: "disable"
        dhcp_snooping_option82: "disable"
        dhcp_snooping_verify_mac: "disable"
        dhcp6_snooping: "disable"
        id:  "16"
        igmp_snooping: "enable"
        igmp_snooping_fast_leave: "enable"
        igmp_snooping_proxy: "enable"
        igmp_snooping_querier: "enable"
        igmp_snooping_querier_addr: "<your_own_value>"
        igmp_snooping_querier_version: "22"
        igmp_snooping_static_group:
         -
            mcast_addr: "<your_own_value>"
            members:
             -
                member_name: "<your_own_value> (source switch.interface.name)"
            name: "default_name_27"
        isolated_vlan: "28"
        lan_segment: "enable"
        lan_segment_primary_vlan: "30"
        lan_segment_type: "31"
        lan_subvlans: "<your_own_value>"
        learning: "disable"
        learning_limit: "34"
        member_by_ipv4:
         -
            address: "<your_own_value>"
            description: "<your_own_value>"
            id:  "38"
        member_by_ipv6:
         -
            description: "<your_own_value>"
            id:  "41"
            prefix: "<your_own_value>"
        member_by_mac:
         -
            description: "<your_own_value>"
            id:  "45"
            mac: "<your_own_value>"
        member_by_proto:
         -
            description: "<your_own_value>"
            frametypes: "ethernet2"
            id:  "50"
            protocol: "51"
        mld_snooping: "enable"
        mld_snooping_fast_leave: "enable"
        mld_snooping_proxy: "enable"
        mld_snooping_querier: "enable"
        mld_snooping_querier_addr: "<your_own_value>"
        mld_snooping_static_group:
         -
            mcast_addr: "<your_own_value>"
            members:
             -
                member_name: "<your_own_value> (source switch.interface.name)"
            name: "default_name_61"
        mrouter_ports:
         -
            member_name: "<your_own_value>"
        policer: "64 (source switch.acl.policer.id)"
        primary_vlan: "65"
        private_vlan: "enable"
        private_vlan_type: "67"
        rspan_mode: "enable"

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
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.secret_field import is_secret_field


def filter_switch_vlan_data(json):
    option_list = ['access_vlan', 'arp_inspection', 'community_vlans',
                   'cos_queue', 'description', 'dhcp_server_access_list',
                   'dhcp_snooping', 'dhcp_snooping_option82', 'dhcp_snooping_verify_mac',
                   'dhcp6_snooping', 'id', 'igmp_snooping',
                   'igmp_snooping_fast_leave', 'igmp_snooping_proxy', 'igmp_snooping_querier',
                   'igmp_snooping_querier_addr', 'igmp_snooping_querier_version', 'igmp_snooping_static_group',
                   'isolated_vlan', 'lan_segment', 'lan_segment_primary_vlan',
                   'lan_segment_type', 'lan_subvlans', 'learning',
                   'learning_limit', 'member_by_ipv4', 'member_by_ipv6',
                   'member_by_mac', 'member_by_proto', 'mld_snooping',
                   'mld_snooping_fast_leave', 'mld_snooping_proxy', 'mld_snooping_querier',
                   'mld_snooping_querier_addr', 'mld_snooping_static_group', 'mrouter_ports',
                   'policer', 'primary_vlan', 'private_vlan',
                   'private_vlan_type', 'rspan_mode']

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


def switch_vlan(data, fos, check_mode=False):

    state = data['state']

    switch_vlan_data = data['switch_vlan']
    filtered_data = underscore_to_hyphen(filter_switch_vlan_data(switch_vlan_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('switch', 'vlan', filtered_data)
        current_data = fos.get('switch', 'vlan', mkey=mkey)
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
                       'vlan',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('switch',
                          'vlan',
                          mkey=filtered_data['id'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_switch(data, fos, check_mode):

    fos.do_member_operation('switch', 'vlan')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_vlan']:
        resp = switch_vlan(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_vlan'))
    if check_mode:
        return resp
    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "elements": "dict",
    "type": "list",
    "children": {
        "lan_segment_type": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True
            }
        },
        "arp_inspection": {
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
        "dhcp_snooping": {
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
        "primary_vlan": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "lan_segment_primary_vlan": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True
            }
        },
        "igmp_snooping_static_group": {
            "elements": "dict",
            "type": "list",
            "children": {
                "mcast_addr": {
                    "type": "string",
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
                "members": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "member_name": {
                            "type": "string",
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
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "isolated_vlan": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "policer": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "learning": {
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
        "private_vlan": {
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
        "dhcp_snooping_verify_mac": {
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
        "mld_snooping_querier_addr": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "id": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "member_by_proto": {
            "elements": "dict",
            "type": "list",
            "children": {
                "frametypes": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ethernet2",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "802.3d",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "llc",
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
                "protocol": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "description": {
                    "type": "string",
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
        "access_vlan": {
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
        "mrouter_ports": {
            "elements": "dict",
            "type": "list",
            "children": {
                "member_name": {
                    "type": "string",
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
        "mld_snooping_proxy": {
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
        "lan_subvlans": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True
            }
        },
        "mld_snooping_fast_leave": {
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
        "igmp_snooping_proxy": {
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
        "igmp_snooping": {
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
        "igmp_snooping_querier": {
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
        "private_vlan_type": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "description": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "mld_snooping_querier": {
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
        "dhcp_server_access_list": {
            "elements": "dict",
            "type": "list",
            "children": {
                "server_ip6": {
                    "type": "string",
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
                "server_ip": {
                    "type": "string",
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
        "dhcp6_snooping": {
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
        "cos_queue": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "mld_snooping": {
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
        "member_by_ipv4": {
            "elements": "dict",
            "type": "list",
            "children": {
                "address": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "description": {
                    "type": "string",
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
        "member_by_mac": {
            "elements": "dict",
            "type": "list",
            "children": {
                "mac": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "description": {
                    "type": "string",
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
        "lan_segment": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True
                    }
                },
                {
                    "value": "disable",
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
        "community_vlans": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "igmp_snooping_querier_version": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "rspan_mode": {
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
        "igmp_snooping_fast_leave": {
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
        "member_by_ipv6": {
            "elements": "dict",
            "type": "list",
            "children": {
                "prefix": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "description": {
                    "type": "string",
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
        "dhcp_snooping_option82": {
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
        "learning_limit": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "mld_snooping_static_group": {
            "elements": "dict",
            "type": "list",
            "children": {
                "mcast_addr": {
                    "type": "string",
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
                "members": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "member_name": {
                            "type": "string",
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
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "igmp_snooping_querier_addr": {
            "type": "string",
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
    mkeyname = 'id'
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
        "switch_vlan": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_vlan"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_vlan"]['options'][attribute_name]['required'] = True

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=True)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_vlan")

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
