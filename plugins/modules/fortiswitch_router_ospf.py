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
module: fortiswitch_router_ospf
short_description: OSPF configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and ospf category.
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
    
    router_ospf:
        description:
            - OSPF configuration.
        default: null
        type: dict
        suboptions:
            abr_type:
                description:
                    - Area border router type.
                type: str
                choices:
                    - cisco
                    - ibm
                    - shortcut
                    - standard
            area:
                description:
                    - OSPF area configuration.
                type: list
                suboptions:
                    default_cost:
                        description:
                            - Summary default cost of stub or NSSA area.
                        type: int
                    filter_list:
                        description:
                            - OSPF area filter-list configuration.
                        type: list
                        suboptions:
                            direction:
                                description:
                                    - Direction.
                                type: str
                                choices:
                                    - in
                                    - out
                            id:
                                description:
                                    - Filter list entry ID.
                                required: true
                                type: int
                            list:
                                description:
                                    - Access-list or prefix-list name. Source router.access-list.name router.prefix-list.name.
                                type: str
                    id:
                        description:
                            - Area entry IP address.
                        required: true
                        type: str
                    nssa_translator_role:
                        description:
                            - NSSA translator role type.
                        type: str
                        choices:
                            - candidate
                            - never
                            - always
                    range:
                        description:
                            - OSPF area range configuration.
                        type: list
                        suboptions:
                            advertise:
                                description:
                                    - Enable/disable advertise status.
                                type: str
                                choices:
                                    - disable
                                    - enable
                            id:
                                description:
                                    - Range entry ID.
                                required: true
                                type: int
                            prefix:
                                description:
                                    - Prefix.
                                type: str
                            substitute:
                                description:
                                    - Substitute prefix.
                                type: str
                            substitute_status:
                                description:
                                    - Enable/disable substitute status.
                                type: str
                                choices:
                                    - enable
                                    - disable
                    shortcut:
                        description:
                            - Enable/disable shortcut option.
                        type: str
                        choices:
                            - disable
                            - enable
                            - default
                    stub_type:
                        description:
                            - Stub summary setting.
                        type: str
                        choices:
                            - no-summary
                            - summary
                    type:
                        description:
                            - Area type setting.
                        type: str
                        choices:
                            - regular
                            - nssa
                            - stub
                    virtual_link:
                        description:
                            - OSPF virtual link configuration.
                        type: list
                        suboptions:
                            authentication:
                                description:
                                    - Authentication type.
                                type: str
                                choices:
                                    - none
                                    - text
                                    - md5
                            authentication_key:
                                description:
                                    - Authentication key.
                                type: str
                            dead_interval:
                                description:
                                    - Dead interval.
                                type: int
                            hello_interval:
                                description:
                                    - Hello interval.
                                type: int
                            md5_keys:
                                description:
                                    - OSPF md5 key configuration. Applicable only when authentication field is set to md5.
                                type: list
                                suboptions:
                                    id:
                                        description:
                                            - key-id (1-255).
                                        required: true
                                        type: int
                                    key:
                                        description:
                                            - md5-key.
                                        type: str
                            name:
                                description:
                                    - Virtual link entry name.
                                required: true
                                type: str
                            peer:
                                description:
                                    - Peer IP.
                                type: str
                            retransmit_interval:
                                description:
                                    - Time between retransmitting lost link state advertisements.
                                type: int
                            transmit_delay:
                                description:
                                    - Link state transmit delay.
                                type: int
            database_overflow:
                description:
                    - Enable/disable database overflow.
                type: str
                choices:
                    - enable
                    - disable
            database_overflow_max_external_lsa:
                description:
                    - Database overflow maximum External LSAs.
                type: int
            database_overflow_time_to_recover:
                description:
                    - Database overflow time to recover (sec).
                type: int
            default_information_metric:
                description:
                    - Default information metric.
                type: int
            default_information_metric_type:
                description:
                    - Default information metric type.
                type: str
                choices:
                    - 1
                    - 2
            default_information_originate:
                description:
                    - Enable/disable generation of default route.
                type: str
                choices:
                    - enable
                    - always
                    - disable
            distance:
                description:
                    - Administrative distance.
                type: int
            distance_external:
                description:
                    - Administrative external route distance.
                type: int
            distance_inter_area:
                description:
                    - Administrative inter-area route distance.
                type: int
            distance_intra_area:
                description:
                    - Administrative intra-area route distance.
                type: int
            distribute_list:
                description:
                    - Redistribute routes filter.
                type: list
                suboptions:
                    access_list:
                        description:
                            - Access list name. Source router.access-list.name.
                        type: str
                    id:
                        description:
                            - Distribute list entry ID.
                        required: true
                        type: int
                    protocol:
                        description:
                            - Protocol type.
                        type: str
                        choices:
                            - connected
                            - static
                            - rip
                            - bgp
                            - isis
            interface:
                description:
                    - OSPF interface configuration.
                type: list
                suboptions:
                    authentication:
                        description:
                            - Authentication type.
                        type: str
                        choices:
                            - none
                            - text
                            - md5
                    authentication_key:
                        description:
                            - Authentication key.
                        type: str
                    bfd:
                        description:
                            - Bidirectional Forwarding Detection (BFD).
                        type: str
                        choices:
                            - enable
                            - disable
                    cost:
                        description:
                            - Cost of the interface.
                        type: int
                    dead_interval:
                        description:
                            - Dead interval. For fast-hello assign value 1.
                        type: int
                    hello_interval:
                        description:
                            - Hello interval.
                        type: int
                    hello_multiplier:
                        description:
                            - Number of hello packets within dead interval.Valid only for fast-hello.
                        type: int
                    md5_keys:
                        description:
                            - OSPF md5 key configuration. Applicable only when authentication field is set to md5.
                        type: list
                        suboptions:
                            id:
                                description:
                                    - key-id (1-255).
                                required: true
                                type: int
                            key:
                                description:
                                    - md5-key.
                                type: str
                    mtu:
                        description:
                            - Interface MTU.
                        type: int
                    mtu_ignore:
                        description:
                            - Disable MTU mismatch detection on this interface.
                        type: str
                        choices:
                            - enable
                            - disable
                    name:
                        description:
                            - Interface entry name. Source system.interface.name.
                        required: true
                        type: str
                    priority:
                        description:
                            - Router priority.
                        type: int
                    retransmit_interval:
                        description:
                            - Time between retransmitting lost link state advertisements.
                        type: int
                    transmit_delay:
                        description:
                            - Link state transmit delay.
                        type: int
                    ucast_ttl:
                        description:
                            - Unicast TTL.
                        type: int
            log_neighbour_changes:
                description:
                    - Enable logging of OSPF neighbour"s changes
                type: str
                choices:
                    - enable
                    - disable
            name:
                description:
                    - Vrf name.
                type: str
            network:
                description:
                    - Enable OSPF on an IP network.
                type: list
                suboptions:
                    area:
                        description:
                            - Attach the network to area.
                        type: str
                    id:
                        description:
                            - Network entry ID.
                        required: true
                        type: int
                    prefix:
                        description:
                            - Prefix.
                        type: str
            passive_interface:
                description:
                    - Passive interface configuration.
                type: list
                suboptions:
                    name:
                        description:
                            - Passive interface name. Source system.interface.name.
                        required: true
                        type: str
            redistribute:
                description:
                    - Redistribute configuration.
                type: list
                suboptions:
                    metric:
                        description:
                            - Redistribute metric setting.
                        type: int
                    metric_type:
                        description:
                            - Metric type.
                        type: str
                        choices:
                            - 1
                            - 2
                    name:
                        description:
                            - Redistribute name.
                        required: true
                        type: str
                    routemap:
                        description:
                            - Route map name. Source router.route-map.name.
                        type: str
                    status:
                        description:
                            - status
                        type: str
                        choices:
                            - enable
                            - disable
                    tag:
                        description:
                            - Tag value.
                        type: int
            rfc1583_compatible:
                description:
                    - Enable/disable RFC1583 compatibility.
                type: str
                choices:
                    - enable
                    - disable
            router_id:
                description:
                    - Router ID.
                type: str
            spf_timers:
                description:
                    - SPF calculation frequency.
                type: str
            summary_address:
                description:
                    - Aggregate address for redistributed routes.
                type: list
                suboptions:
                    id:
                        description:
                            - Summary address entry ID.
                        required: true
                        type: int
                    prefix:
                        description:
                            - Prefix.
                        type: str
                    tag:
                        description:
                            - Tag value.
                        type: int
            vrf:
                description:
                    - Enable OSPF on VRF.
                type: list
                suboptions:
                    abr_type:
                        description:
                            - Area border router type.
                        type: str
                        choices:
                            - cisco
                            - ibm
                            - shortcut
                            - standard
                    area:
                        description:
                            - OSPF area configuration.
                        type: list
                        suboptions:
                            default_cost:
                                description:
                                    - Summary default cost of stub or NSSA area.
                                type: int
                            filter_list:
                                description:
                                    - OSPF area filter-list configuration.
                                type: list
                                suboptions:
                                    direction:
                                        description:
                                            - Direction.
                                        type: str
                                        choices:
                                            - in
                                            - out
                                    id:
                                        description:
                                            - Filter list entry ID.
                                        required: true
                                        type: int
                                    list:
                                        description:
                                            - Access-list or prefix-list name. Source router.access-list.name router.prefix-list.name.
                                        type: str
                            id:
                                description:
                                    - Area entry IP address.
                                required: true
                                type: str
                            nssa_translator_role:
                                description:
                                    - NSSA translator role type.
                                type: str
                                choices:
                                    - candidate
                                    - never
                                    - always
                            range:
                                description:
                                    - OSPF area range configuration.
                                type: list
                                suboptions:
                                    advertise:
                                        description:
                                            - Enable/disable advertise status.
                                        type: str
                                        choices:
                                            - disable
                                            - enable
                                    id:
                                        description:
                                            - Range entry ID.
                                        required: true
                                        type: int
                                    prefix:
                                        description:
                                            - Prefix.
                                        type: str
                                    substitute:
                                        description:
                                            - Substitute prefix.
                                        type: str
                                    substitute_status:
                                        description:
                                            - Enable/disable substitute status.
                                        type: str
                                        choices:
                                            - enable
                                            - disable
                            shortcut:
                                description:
                                    - Enable/disable shortcut option.
                                type: str
                                choices:
                                    - disable
                                    - enable
                                    - default
                            stub_type:
                                description:
                                    - Stub summary setting.
                                type: str
                                choices:
                                    - no-summary
                                    - summary
                            type:
                                description:
                                    - Area type setting.
                                type: str
                                choices:
                                    - regular
                                    - nssa
                                    - stub
                            virtual_link:
                                description:
                                    - OSPF virtual link configuration.
                                type: list
                                suboptions:
                                    authentication:
                                        description:
                                            - Authentication type.
                                        type: str
                                        choices:
                                            - none
                                            - text
                                    authentication_key:
                                        description:
                                            - Authentication key.
                                        type: str
                                    dead_interval:
                                        description:
                                            - Dead interval.
                                        type: int
                                    hello_interval:
                                        description:
                                            - Hello interval.
                                        type: int
                                    name:
                                        description:
                                            - Virtual link entry name.
                                        required: true
                                        type: str
                                    peer:
                                        description:
                                            - Peer IP.
                                        type: str
                                    retransmit_interval:
                                        description:
                                            - Time between retransmitting lost link state advertisements.
                                        type: int
                                    transmit_delay:
                                        description:
                                            - Link state transmit delay.
                                        type: int
                    database_overflow:
                        description:
                            - Enable/disable database overflow.
                        type: str
                        choices:
                            - enable
                            - disable
                    database_overflow_max_external_lsa:
                        description:
                            - Database overflow maximum External LSAs.
                        type: int
                    database_overflow_time_to_recover:
                        description:
                            - Database overflow time to recover (sec).
                        type: int
                    default_information_metric:
                        description:
                            - Default information metric.
                        type: int
                    default_information_metric_type:
                        description:
                            - Default information metric type.
                        type: str
                        choices:
                            - 1
                            - 2
                    default_information_originate:
                        description:
                            - Enable/disable generation of default route.
                        type: str
                        choices:
                            - enable
                            - always
                            - disable
                    distance:
                        description:
                            - Administrative distance.
                        type: int
                    distance_external:
                        description:
                            - Administrative external route distance.
                        type: int
                    distance_inter_area:
                        description:
                            - Administrative inter-area route distance.
                        type: int
                    distance_intra_area:
                        description:
                            - Administrative intra-area route distance.
                        type: int
                    distribute_list:
                        description:
                            - Redistribute routes filter.
                        type: list
                        suboptions:
                            access_list:
                                description:
                                    - Access list name. Source router.access-list.name.
                                type: str
                            id:
                                description:
                                    - Distribute list entry ID.
                                required: true
                                type: int
                            protocol:
                                description:
                                    - Protocol type.
                                type: str
                                choices:
                                    - connected
                                    - static
                                    - rip
                                    - bgp
                                    - isis
                    interface:
                        description:
                            - OSPF interface configuration.
                        type: list
                        suboptions:
                            authentication:
                                description:
                                    - Authentication type.
                                type: str
                                choices:
                                    - none
                                    - text
                                    - md5
                            authentication_key:
                                description:
                                    - Authentication key.
                                type: str
                            cost:
                                description:
                                    - Cost of the interface.
                                type: int
                            dead_interval:
                                description:
                                    - Dead interval. For fast-hello assign value 1.
                                type: int
                            hello_interval:
                                description:
                                    - Hello interval.
                                type: int
                            hello_multiplier:
                                description:
                                    - Number of hello packets within dead interval.Valid only for fast-hello.
                                type: int
                            md5_keys:
                                description:
                                    - OSPF md5 key configuration. Applicable only when authentication field is set to md5.
                                type: list
                                suboptions:
                                    id:
                                        description:
                                            - key-id (1-255).
                                        required: true
                                        type: int
                                    key:
                                        description:
                                            - md5-key.
                                        type: str
                            mtu:
                                description:
                                    - Interface MTU.
                                type: int
                            mtu_ignore:
                                description:
                                    - Disable MTU mismatch detection on this interface.
                                type: str
                                choices:
                                    - enable
                                    - disable
                            name:
                                description:
                                    - Interface entry name. Source system.interface.name.
                                required: true
                                type: str
                            priority:
                                description:
                                    - Router priority.
                                type: int
                            retransmit_interval:
                                description:
                                    - Time between retransmitting lost link state advertisements.
                                type: int
                            transmit_delay:
                                description:
                                    - Link state transmit delay.
                                type: int
                            ucast_ttl:
                                description:
                                    - Unicast TTL.
                                type: int
                    log_neighbour_changes:
                        description:
                            - Enable logging of OSPF neighbour"s changes
                        type: str
                        choices:
                            - enable
                            - disable
                    name:
                        description:
                            - Vrf name. Source router.vrf.name.
                        required: true
                        type: str
                    network:
                        description:
                            - Enable OSPF on an IP network.
                        type: list
                        suboptions:
                            area:
                                description:
                                    - Attach the network to area.
                                type: str
                            id:
                                description:
                                    - Network entry ID.
                                required: true
                                type: int
                            prefix:
                                description:
                                    - Prefix.
                                type: str
                    passive_interface:
                        description:
                            - Passive interface configuration.
                        type: list
                        suboptions:
                            name:
                                description:
                                    - Passive interface name. Source system.interface.name.
                                required: true
                                type: str
                    redistribute:
                        description:
                            - Redistribute configuration.
                        type: list
                        suboptions:
                            metric:
                                description:
                                    - Redistribute metric setting.
                                type: int
                            metric_type:
                                description:
                                    - Metric type.
                                type: str
                                choices:
                                    - 1
                                    - 2
                            name:
                                description:
                                    - Redistribute name.
                                required: true
                                type: str
                            routemap:
                                description:
                                    - Route map name. Source router.route-map.name.
                                type: str
                            status:
                                description:
                                    - status
                                type: str
                                choices:
                                    - enable
                                    - disable
                            tag:
                                description:
                                    - Tag value.
                                type: int
                    rfc1583_compatible:
                        description:
                            - Enable/disable RFC1583 compatibility.
                        type: str
                        choices:
                            - enable
                            - disable
                    router_id:
                        description:
                            - Router ID.
                        type: str
                    spf_timers:
                        description:
                            - SPF calculation frequency.
                        type: str
                    summary_address:
                        description:
                            - Aggregate address for redistributed routes.
                        type: list
                        suboptions:
                            id:
                                description:
                                    - Summary address entry ID.
                                required: true
                                type: int
                            prefix:
                                description:
                                    - Prefix.
                                type: str
                            tag:
                                description:
                                    - Tag value.
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
  - name: OSPF configuration.
    fortiswitch_router_ospf:
      state: "present"
      router_ospf:
        abr_type: "cisco"
        area:
         -
            default_cost: "5"
            filter_list:
             -
                direction: "in"
                id:  "8"
                list: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
            id:  "10"
            nssa_translator_role: "candidate"
            range:
             -
                advertise: "disable"
                id:  "14"
                prefix: "<your_own_value>"
                substitute: "<your_own_value>"
                substitute_status: "enable"
            shortcut: "disable"
            stub_type: "no-summary"
            type: "regular"
            virtual_link:
             -
                authentication: "none"
                authentication_key: "<your_own_value>"
                dead_interval: "24"
                hello_interval: "25"
                md5_keys:
                 -
                    id:  "27"
                    key: "<your_own_value>"
                name: "default_name_29"
                peer: "<your_own_value>"
                retransmit_interval: "31"
                transmit_delay: "32"
        database_overflow: "enable"
        database_overflow_max_external_lsa: "34"
        database_overflow_time_to_recover: "35"
        default_information_metric: "36"
        default_information_metric_type: "1"
        default_information_originate: "enable"
        distance: "39"
        distance_external: "40"
        distance_inter_area: "41"
        distance_intra_area: "42"
        distribute_list:
         -
            access_list: "<your_own_value> (source router.access-list.name)"
            id:  "45"
            protocol: "connected"
        interface:
         -
            authentication: "none"
            authentication_key: "<your_own_value>"
            bfd: "enable"
            cost: "51"
            dead_interval: "52"
            hello_interval: "53"
            hello_multiplier: "54"
            md5_keys:
             -
                id:  "56"
                key: "<your_own_value>"
            mtu: "58"
            mtu_ignore: "enable"
            name: "default_name_60 (source system.interface.name)"
            priority: "61"
            retransmit_interval: "62"
            transmit_delay: "63"
            ucast_ttl: "64"
        log_neighbour_changes: "enable"
        name: "default_name_66"
        network:
         -
            area: "<your_own_value>"
            id:  "69"
            prefix: "<your_own_value>"
        passive_interface:
         -
            name: "default_name_72 (source system.interface.name)"
        redistribute:
         -
            metric: "74"
            metric_type: "1"
            name: "default_name_76"
            routemap: "<your_own_value> (source router.route-map.name)"
            status: "enable"
            tag: "79"
        rfc1583_compatible: "enable"
        router_id: "<your_own_value>"
        spf_timers: "<your_own_value>"
        summary_address:
         -
            id:  "84"
            prefix: "<your_own_value>"
            tag: "86"
        vrf:
         -
            abr_type: "cisco"
            area:
             -
                default_cost: "90"
                filter_list:
                 -
                    direction: "in"
                    id:  "93"
                    list: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
                id:  "95"
                nssa_translator_role: "candidate"
                range:
                 -
                    advertise: "disable"
                    id:  "99"
                    prefix: "<your_own_value>"
                    substitute: "<your_own_value>"
                    substitute_status: "enable"
                shortcut: "disable"
                stub_type: "no-summary"
                type: "regular"
                virtual_link:
                 -
                    authentication: "none"
                    authentication_key: "<your_own_value>"
                    dead_interval: "109"
                    hello_interval: "110"
                    name: "default_name_111"
                    peer: "<your_own_value>"
                    retransmit_interval: "113"
                    transmit_delay: "114"
            database_overflow: "enable"
            database_overflow_max_external_lsa: "116"
            database_overflow_time_to_recover: "117"
            default_information_metric: "118"
            default_information_metric_type: "1"
            default_information_originate: "enable"
            distance: "121"
            distance_external: "122"
            distance_inter_area: "123"
            distance_intra_area: "124"
            distribute_list:
             -
                access_list: "<your_own_value> (source router.access-list.name)"
                id:  "127"
                protocol: "connected"
            interface:
             -
                authentication: "none"
                authentication_key: "<your_own_value>"
                cost: "132"
                dead_interval: "133"
                hello_interval: "134"
                hello_multiplier: "135"
                md5_keys:
                 -
                    id:  "137"
                    key: "<your_own_value>"
                mtu: "139"
                mtu_ignore: "enable"
                name: "default_name_141 (source system.interface.name)"
                priority: "142"
                retransmit_interval: "143"
                transmit_delay: "144"
                ucast_ttl: "145"
            log_neighbour_changes: "enable"
            name: "default_name_147 (source router.vrf.name)"
            network:
             -
                area: "<your_own_value>"
                id:  "150"
                prefix: "<your_own_value>"
            passive_interface:
             -
                name: "default_name_153 (source system.interface.name)"
            redistribute:
             -
                metric: "155"
                metric_type: "1"
                name: "default_name_157"
                routemap: "<your_own_value> (source router.route-map.name)"
                status: "enable"
                tag: "160"
            rfc1583_compatible: "enable"
            router_id: "<your_own_value>"
            spf_timers: "<your_own_value>"
            summary_address:
             -
                id:  "165"
                prefix: "<your_own_value>"
                tag: "167"

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
def filter_router_ospf_data(json):
    option_list = ['abr_type', 'area', 'database_overflow',
                   'database_overflow_max_external_lsa', 'database_overflow_time_to_recover', 'default_information_metric',
                   'default_information_metric_type', 'default_information_originate', 'distance',
                   'distance_external', 'distance_inter_area', 'distance_intra_area',
                   'distribute_list', 'interface', 'log_neighbour_changes',
                   'name', 'network', 'passive_interface',
                   'redistribute', 'rfc1583_compatible', 'router_id',
                   'spf_timers', 'summary_address', 'vrf' ]
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

def router_ospf(data, fos):
    router_ospf_data = data['router_ospf']
    filtered_data = underscore_to_hyphen(filter_router_ospf_data(router_ospf_data))

    
    return fos.set('router',
                    'ospf',
                    data=filtered_data,
                    )
    

def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404




def fortiswitch_router(data, fos):

    fos.do_member_operation('router_ospf')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['router_ospf']:
        resp = router_ospf(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('router_ospf'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp



versioned_schema = {
    "type": "dict", 
    "children": {
        "default_information_metric": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "distance_intra_area": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "default_information_metric_type": {
            "type": "string", 
            "options": [
                {
                    "value": "1", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "2", 
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
        "network": {
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
                "area": {
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
        "area": {
            "type": "list", 
            "children": {
                "stub_type": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "no-summary", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "summary", 
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
                "shortcut": {
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
                        }, 
                        {
                            "value": "default", 
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
                "default_cost": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "range": {
                    "type": "list", 
                    "children": {
                        "substitute_status": {
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
                        "advertise": {
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
                        "prefix": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "substitute": {
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
                        }
                    }, 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "nssa_translator_role": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "candidate", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "never", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "always", 
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
                "virtual_link": {
                    "type": "list", 
                    "children": {
                        "retransmit_interval": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "md5_keys": {
                            "type": "list", 
                            "children": {
                                "id": {
                                    "type": "integer", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                "key": {
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
                        "name": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "authentication": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "none", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "text", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "md5", 
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
                        "dead_interval": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "hello_interval": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "peer": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "authentication_key": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "transmit_delay": {
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
                "filter_list": {
                    "type": "list", 
                    "children": {
                        "direction": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "in", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "out", 
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
                        "list": {
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
                        }
                    }, 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "type": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "regular", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "nssa", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "stub", 
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
                "id": {
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
        "distribute_list": {
            "type": "list", 
            "children": {
                "protocol": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "connected", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "static", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "rip", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "bgp", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "isis", 
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
                "id": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "access_list": {
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
        "abr_type": {
            "type": "string", 
            "options": [
                {
                    "value": "cisco", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "ibm", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "shortcut", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "standard", 
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
        "default_information_originate": {
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
                    "value": "always", 
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
        "database_overflow_max_external_lsa": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "passive_interface": {
            "type": "list", 
            "children": {
                "name": {
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
        "router_id": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "distance_inter_area": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "log_neighbour_changes": {
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
        "distance_external": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "summary_address": {
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
                "tag": {
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
                }
            }, 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "spf_timers": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "vrf": {
            "type": "list", 
            "children": {
                "default_information_metric": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "distance_intra_area": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "default_information_metric_type": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "1", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "2", 
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
                "network": {
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
                        "area": {
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
                "area": {
                    "type": "list", 
                    "children": {
                        "stub_type": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "no-summary", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "summary", 
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
                        "shortcut": {
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
                                }, 
                                {
                                    "value": "default", 
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
                        "default_cost": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "range": {
                            "type": "list", 
                            "children": {
                                "substitute_status": {
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
                                "advertise": {
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
                                "prefix": {
                                    "type": "string", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                "substitute": {
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
                                }
                            }, 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "nssa_translator_role": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "candidate", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "never", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "always", 
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
                        "virtual_link": {
                            "type": "list", 
                            "children": {
                                "retransmit_interval": {
                                    "type": "integer", 
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
                                "authentication": {
                                    "type": "string", 
                                    "options": [
                                        {
                                            "value": "none", 
                                            "revisions": {
                                                "v7.0.3": True, 
                                                "v7.0.2": True, 
                                                "v7.0.1": True, 
                                                "v7.0.0": True
                                            }
                                        }, 
                                        {
                                            "value": "text", 
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
                                "dead_interval": {
                                    "type": "integer", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                "hello_interval": {
                                    "type": "integer", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                "peer": {
                                    "type": "string", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                "authentication_key": {
                                    "type": "string", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                "transmit_delay": {
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
                        "filter_list": {
                            "type": "list", 
                            "children": {
                                "direction": {
                                    "type": "string", 
                                    "options": [
                                        {
                                            "value": "in", 
                                            "revisions": {
                                                "v7.0.3": True, 
                                                "v7.0.2": True, 
                                                "v7.0.1": True, 
                                                "v7.0.0": True
                                            }
                                        }, 
                                        {
                                            "value": "out", 
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
                                "list": {
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
                                }
                            }, 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "type": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "regular", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "nssa", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "stub", 
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
                        "id": {
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
                "distribute_list": {
                    "type": "list", 
                    "children": {
                        "protocol": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "connected", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "static", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "rip", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "bgp", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "isis", 
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
                        "id": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "access_list": {
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
                "abr_type": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "cisco", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "ibm", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "shortcut", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "standard", 
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
                "default_information_originate": {
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
                            "value": "always", 
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
                "database_overflow_max_external_lsa": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "passive_interface": {
                    "type": "list", 
                    "children": {
                        "name": {
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
                "router_id": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "distance_inter_area": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "log_neighbour_changes": {
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
                "distance_external": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "summary_address": {
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
                        "tag": {
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
                        }
                    }, 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "spf_timers": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "interface": {
                    "type": "list", 
                    "children": {
                        "retransmit_interval": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "md5_keys": {
                            "type": "list", 
                            "children": {
                                "id": {
                                    "type": "integer", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                "key": {
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
                        "cost": {
                            "type": "integer", 
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
                        "authentication": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "none", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "text", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "md5", 
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
                        "mtu_ignore": {
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
                        "priority": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "hello_multiplier": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "dead_interval": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "hello_interval": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "ucast_ttl": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True
                            }
                        }, 
                        "authentication_key": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "mtu": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "transmit_delay": {
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
                "distance": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "redistribute": {
                    "type": "list", 
                    "children": {
                        "status": {
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
                        "metric": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "tag": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "metric_type": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "1", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "2", 
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
                        "routemap": {
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
                "name": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "database_overflow": {
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
                "database_overflow_time_to_recover": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "rfc1583_compatible": {
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
                }
            }, 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "interface": {
            "type": "list", 
            "children": {
                "retransmit_interval": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "md5_keys": {
                    "type": "list", 
                    "children": {
                        "id": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "key": {
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
                "cost": {
                    "type": "integer", 
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
                "bfd": {
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
                "authentication": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "none", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "text", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "md5", 
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
                "mtu": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "priority": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "hello_multiplier": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "dead_interval": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "hello_interval": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "ucast_ttl": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True
                    }
                }, 
                "authentication_key": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "mtu_ignore": {
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
                "transmit_delay": {
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
        "distance": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "redistribute": {
            "type": "list", 
            "children": {
                "status": {
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
                "metric": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "tag": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "metric_type": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "1", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "2", 
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
                "routemap": {
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
        "name": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "database_overflow": {
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
        "database_overflow_time_to_recover": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "rfc1583_compatible": {
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
        "router_ospf": {
            "required": False, "type": "dict", "default": None,
            "options": { 
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["router_ospf"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["router_ospf"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "router_ospf")
        
        is_error, has_changed, result = fortiswitch_router(module.params, fos)
        
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