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
module: fortiswitch_router_ospf
short_description: OSPF configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and ospf category.
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
                    - 'cisco'
                    - 'ibm'
                    - 'shortcut'
                    - 'standard'
            area:
                description:
                    - OSPF area configuration.
                type: list
                elements: dict
                suboptions:
                    default_cost:
                        description:
                            - Summary default cost of stub or NSSA area.
                        type: int
                    filter_list:
                        description:
                            - OSPF area filter-list configuration.
                        type: list
                        elements: dict
                        suboptions:
                            direction:
                                description:
                                    - Direction.
                                type: str
                                choices:
                                    - 'in'
                                    - 'out'
                            id:
                                description:
                                    - Filter list entry ID.
                                type: int
                            list:
                                description:
                                    - Access-list or prefix-list name.
                                type: str
                    id:
                        description:
                            - Area entry IP address.
                        type: str
                    nssa_translator_role:
                        description:
                            - NSSA translator role type.
                        type: str
                        choices:
                            - 'candidate'
                            - 'never'
                            - 'always'
                    range:
                        description:
                            - OSPF area range configuration.
                        type: list
                        elements: dict
                        suboptions:
                            advertise:
                                description:
                                    - Enable/disable advertise status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            id:
                                description:
                                    - Range entry ID.
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
                                    - 'enable'
                                    - 'disable'
                    shortcut:
                        description:
                            - Enable/disable shortcut option.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
                    stub_type:
                        description:
                            - Stub summary setting.
                        type: str
                        choices:
                            - 'no_summary'
                            - 'summary'
                    type:
                        description:
                            - Area type setting.
                        type: str
                        choices:
                            - 'regular'
                            - 'nssa'
                            - 'stub'
                    virtual_link:
                        description:
                            - OSPF virtual link configuration.
                        type: list
                        elements: dict
                        suboptions:
                            authentication:
                                description:
                                    - Authentication type.
                                type: str
                                choices:
                                    - 'none'
                                    - 'text'
                                    - 'md5'
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
                                elements: dict
                                suboptions:
                                    id:
                                        description:
                                            - key-id (1-255).
                                        type: int
                                    key:
                                        description:
                                            - md5-key.
                                        type: str
                            name:
                                description:
                                    - Virtual link entry name.
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
                    - 'enable'
                    - 'disable'
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
                    - '1'
                    - '2'
            default_information_originate:
                description:
                    - Enable/disable generation of default route.
                type: str
                choices:
                    - 'enable'
                    - 'always'
                    - 'disable'
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
                elements: dict
                suboptions:
                    access_list:
                        description:
                            - Access list name.
                        type: str
                    id:
                        description:
                            - Distribute list entry ID.
                        type: int
                    protocol:
                        description:
                            - Protocol type.
                        type: str
                        choices:
                            - 'connected'
                            - 'static'
                            - 'rip'
                            - 'bgp'
                            - 'isis'
            interface:
                description:
                    - OSPF interface configuration.
                type: list
                elements: dict
                suboptions:
                    authentication:
                        description:
                            - Authentication type.
                        type: str
                        choices:
                            - 'none'
                            - 'text'
                            - 'md5'
                    authentication_key:
                        description:
                            - Authentication key.
                        type: str
                    bfd:
                        description:
                            - Bidirectional Forwarding Detection (BFD).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
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
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - key-id (1-255).
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
                            - 'enable'
                            - 'disable'
                    name:
                        description:
                            - Interface entry name.
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
                    ttl:
                        description:
                            - TTL.
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
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Vrf name.
                type: str
            network:
                description:
                    - Enable OSPF on an IP network.
                type: list
                elements: dict
                suboptions:
                    area:
                        description:
                            - Attach the network to area.
                        type: str
                    id:
                        description:
                            - Network entry ID.
                        type: int
                    prefix:
                        description:
                            - Prefix.
                        type: str
            passive_interface:
                description:
                    - Passive interface configuration.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Passive interface name.
                        type: str
            redistribute:
                description:
                    - Redistribute configuration.
                type: list
                elements: dict
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
                            - '1'
                            - '2'
                    name:
                        description:
                            - Redistribute name.
                        type: str
                    routemap:
                        description:
                            - Route map name.
                        type: str
                    status:
                        description:
                            - status
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tag:
                        description:
                            - Tag value.
                        type: int
            rfc1583_compatible:
                description:
                    - Enable/disable RFC1583 compatibility.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
                elements: dict
                suboptions:
                    id:
                        description:
                            - Summary address entry ID.
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
                elements: dict
                suboptions:
                    abr_type:
                        description:
                            - Area border router type.
                        type: str
                        choices:
                            - 'cisco'
                            - 'ibm'
                            - 'shortcut'
                            - 'standard'
                    area:
                        description:
                            - OSPF area configuration.
                        type: list
                        elements: dict
                        suboptions:
                            default_cost:
                                description:
                                    - Summary default cost of stub or NSSA area.
                                type: int
                            filter_list:
                                description:
                                    - OSPF area filter-list configuration.
                                type: list
                                elements: dict
                                suboptions:
                                    direction:
                                        description:
                                            - Direction.
                                        type: str
                                        choices:
                                            - 'in'
                                            - 'out'
                                    id:
                                        description:
                                            - Filter list entry ID.
                                        type: int
                                    list:
                                        description:
                                            - Access-list or prefix-list name.
                                        type: str
                            id:
                                description:
                                    - Area entry IP address.
                                type: str
                            nssa_translator_role:
                                description:
                                    - NSSA translator role type.
                                type: str
                                choices:
                                    - 'candidate'
                                    - 'never'
                                    - 'always'
                            range:
                                description:
                                    - OSPF area range configuration.
                                type: list
                                elements: dict
                                suboptions:
                                    advertise:
                                        description:
                                            - Enable/disable advertise status.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    id:
                                        description:
                                            - Range entry ID.
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
                                            - 'enable'
                                            - 'disable'
                            shortcut:
                                description:
                                    - Enable/disable shortcut option.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                                    - 'default'
                            stub_type:
                                description:
                                    - Stub summary setting.
                                type: str
                                choices:
                                    - 'no_summary'
                                    - 'summary'
                            type:
                                description:
                                    - Area type setting.
                                type: str
                                choices:
                                    - 'regular'
                                    - 'nssa'
                                    - 'stub'
                            virtual_link:
                                description:
                                    - OSPF virtual link configuration.
                                type: list
                                elements: dict
                                suboptions:
                                    authentication:
                                        description:
                                            - Authentication type.
                                        type: str
                                        choices:
                                            - 'none'
                                            - 'text'
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
                            - 'enable'
                            - 'disable'
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
                            - '1'
                            - '2'
                    default_information_originate:
                        description:
                            - Enable/disable generation of default route.
                        type: str
                        choices:
                            - 'enable'
                            - 'always'
                            - 'disable'
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
                        elements: dict
                        suboptions:
                            access_list:
                                description:
                                    - Access list name.
                                type: str
                            id:
                                description:
                                    - Distribute list entry ID.
                                type: int
                            protocol:
                                description:
                                    - Protocol type.
                                type: str
                                choices:
                                    - 'connected'
                                    - 'static'
                                    - 'rip'
                                    - 'bgp'
                                    - 'isis'
                    interface:
                        description:
                            - OSPF interface configuration.
                        type: list
                        elements: dict
                        suboptions:
                            authentication:
                                description:
                                    - Authentication type.
                                type: str
                                choices:
                                    - 'none'
                                    - 'text'
                                    - 'md5'
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
                                elements: dict
                                suboptions:
                                    id:
                                        description:
                                            - key-id (1-255).
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
                                    - 'enable'
                                    - 'disable'
                            name:
                                description:
                                    - Interface entry name.
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
                            ttl:
                                description:
                                    - TTL.
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
                            - 'enable'
                            - 'disable'
                    name:
                        description:
                            - Vrf name.
                        type: str
                    network:
                        description:
                            - Enable OSPF on an IP network.
                        type: list
                        elements: dict
                        suboptions:
                            area:
                                description:
                                    - Attach the network to area.
                                type: str
                            id:
                                description:
                                    - Network entry ID.
                                type: int
                            prefix:
                                description:
                                    - Prefix.
                                type: str
                    passive_interface:
                        description:
                            - Passive interface configuration.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Passive interface name.
                                type: str
                    redistribute:
                        description:
                            - Redistribute configuration.
                        type: list
                        elements: dict
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
                                    - '1'
                                    - '2'
                            name:
                                description:
                                    - Redistribute name.
                                type: str
                            routemap:
                                description:
                                    - Route map name.
                                type: str
                            status:
                                description:
                                    - status
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tag:
                                description:
                                    - Tag value.
                                type: int
                    rfc1583_compatible:
                        description:
                            - Enable/disable RFC1583 compatibility.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
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
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Summary address entry ID.
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
      router_ospf:
        abr_type: "cisco"
        area:
         -
            default_cost: "5"
            filter_list:
             -
                direction: "in"
                id:  "8"
                list: "<your_own_value> (source router.access_list.name router.prefix_list.name)"
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
            access_list: "<your_own_value> (source router.access_list.name)"
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
            ttl: "64"
            ucast_ttl: "65"
        log_neighbour_changes: "enable"
        name: "default_name_67"
        network:
         -
            area: "<your_own_value>"
            id:  "70"
            prefix: "<your_own_value>"
        passive_interface:
         -
            name: "default_name_73 (source system.interface.name)"
        redistribute:
         -
            metric: "75"
            metric_type: "1"
            name: "default_name_77"
            routemap: "<your_own_value> (source router.route_map.name)"
            status: "enable"
            tag: "80"
        rfc1583_compatible: "enable"
        router_id: "<your_own_value>"
        spf_timers: "<your_own_value>"
        summary_address:
         -
            id:  "85"
            prefix: "<your_own_value>"
            tag: "87"
        vrf:
         -
            abr_type: "cisco"
            area:
             -
                default_cost: "91"
                filter_list:
                 -
                    direction: "in"
                    id:  "94"
                    list: "<your_own_value> (source router.access_list.name router.prefix_list.name)"
                id:  "96"
                nssa_translator_role: "candidate"
                range:
                 -
                    advertise: "disable"
                    id:  "100"
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
                    dead_interval: "110"
                    hello_interval: "111"
                    name: "default_name_112"
                    peer: "<your_own_value>"
                    retransmit_interval: "114"
                    transmit_delay: "115"
            database_overflow: "enable"
            database_overflow_max_external_lsa: "117"
            database_overflow_time_to_recover: "118"
            default_information_metric: "119"
            default_information_metric_type: "1"
            default_information_originate: "enable"
            distance: "122"
            distance_external: "123"
            distance_inter_area: "124"
            distance_intra_area: "125"
            distribute_list:
             -
                access_list: "<your_own_value> (source router.access_list.name)"
                id:  "128"
                protocol: "connected"
            interface:
             -
                authentication: "none"
                authentication_key: "<your_own_value>"
                cost: "133"
                dead_interval: "134"
                hello_interval: "135"
                hello_multiplier: "136"
                md5_keys:
                 -
                    id:  "138"
                    key: "<your_own_value>"
                mtu: "140"
                mtu_ignore: "enable"
                name: "default_name_142 (source system.interface.name)"
                priority: "143"
                retransmit_interval: "144"
                transmit_delay: "145"
                ttl: "146"
                ucast_ttl: "147"
            log_neighbour_changes: "enable"
            name: "default_name_149 (source router.vrf.name)"
            network:
             -
                area: "<your_own_value>"
                id:  "152"
                prefix: "<your_own_value>"
            passive_interface:
             -
                name: "default_name_155 (source system.interface.name)"
            redistribute:
             -
                metric: "157"
                metric_type: "1"
                name: "default_name_159"
                routemap: "<your_own_value> (source router.route_map.name)"
                status: "enable"
                tag: "162"
            rfc1583_compatible: "enable"
            router_id: "<your_own_value>"
            spf_timers: "<your_own_value>"
            summary_address:
             -
                id:  "167"
                prefix: "<your_own_value>"
                tag: "169"

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


def filter_router_ospf_data(json):
    option_list = ['abr_type', 'area', 'database_overflow',
                   'database_overflow_max_external_lsa', 'database_overflow_time_to_recover', 'default_information_metric',
                   'default_information_metric_type', 'default_information_originate', 'distance',
                   'distance_external', 'distance_inter_area', 'distance_intra_area',
                   'distribute_list', 'interface', 'log_neighbour_changes',
                   'name', 'network', 'passive_interface',
                   'redistribute', 'rfc1583_compatible', 'router_id',
                   'spf_timers', 'summary_address', 'vrf']

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
    fos.do_member_operation('router', 'ospf')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['router_ospf']:
        resp = router_ospf(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('router_ospf'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "revisions": {
        "v7.0.0": True,
        "v7.0.1": True,
        "v7.0.2": True,
        "v7.0.3": True,
        "v7.0.4": True,
        "v7.0.5": True,
        "v7.0.6": True,
        "v7.2.1": True,
        "v7.2.2": True,
        "v7.2.3": True,
        "v7.2.4": True,
        "v7.2.5": True,
        "v7.4.0": True
    },
    "type": "dict",
    "children": {
        "summary_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "prefix": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "prefix",
                    "help": "Prefix.",
                    "category": "unitary"
                },
                "tag": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "tag",
                    "help": "Tag value.",
                    "category": "unitary"
                },
                "id": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "id",
                    "help": "Summary address entry ID.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "name": "summary_address",
            "help": "Aggregate address for redistributed routes.",
            "mkey": "id",
            "category": "table"
        },
        "area": {
            "type": "list",
            "elements": "dict",
            "children": {
                "nssa_translator_role": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "candidate",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "never",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "always",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "nssa_translator_role",
                    "help": "NSSA translator role type.",
                    "category": "unitary"
                },
                "virtual_link": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "dead_interval": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "dead_interval",
                            "help": "Dead interval.",
                            "category": "unitary"
                        },
                        "hello_interval": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "hello_interval",
                            "help": "Hello interval.",
                            "category": "unitary"
                        },
                        "name": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "name",
                            "help": "Virtual link entry name.",
                            "category": "unitary"
                        },
                        "transmit_delay": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "transmit_delay",
                            "help": "Link state transmit delay.",
                            "category": "unitary"
                        },
                        "retransmit_interval": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "retransmit_interval",
                            "help": "Time between retransmitting lost link state advertisements.",
                            "category": "unitary"
                        },
                        "authentication": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "none",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "text",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "md5",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "authentication",
                            "help": "Authentication type.",
                            "category": "unitary"
                        },
                        "peer": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "peer",
                            "help": "Peer IP.",
                            "category": "unitary"
                        },
                        "md5_keys": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "id": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "integer",
                                    "name": "id",
                                    "help": "key-id (1-255).",
                                    "category": "unitary"
                                },
                                "key": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "name": "key",
                                    "help": "md5-key.",
                                    "category": "unitary"
                                }
                            },
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "name": "md5_keys",
                            "help": "OSPF md5 key configuration. Applicable only when authentication field is set to md5.",
                            "mkey": "id",
                            "category": "table"
                        },
                        "authentication_key": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "authentication_key",
                            "help": "Authentication key.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "virtual_link",
                    "help": "OSPF virtual link configuration.",
                    "mkey": "name",
                    "category": "table"
                },
                "shortcut": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "default",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "shortcut",
                    "help": "Enable/disable shortcut option.",
                    "category": "unitary"
                },
                "stub_type": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "no_summary",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "summary",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "stub_type",
                    "help": "Stub summary setting.",
                    "category": "unitary"
                },
                "range": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "substitute": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "substitute",
                            "help": "Substitute prefix.",
                            "category": "unitary"
                        },
                        "prefix": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "prefix",
                            "help": "Prefix.",
                            "category": "unitary"
                        },
                        "substitute_status": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "substitute_status",
                            "help": "Enable/disable substitute status.",
                            "category": "unitary"
                        },
                        "id": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "id",
                            "help": "Range entry ID.",
                            "category": "unitary"
                        },
                        "advertise": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "advertise",
                            "help": "Enable/disable advertise status.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "range",
                    "help": "OSPF area range configuration.",
                    "mkey": "id",
                    "category": "table"
                },
                "filter_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "direction": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "in",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "out",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "direction",
                            "help": "Direction.",
                            "category": "unitary"
                        },
                        "list": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "list",
                            "help": "Access-list or prefix-list name.",
                            "category": "unitary"
                        },
                        "id": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "id",
                            "help": "Filter list entry ID.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "filter_list",
                    "help": "OSPF area filter-list configuration.",
                    "mkey": "id",
                    "category": "table"
                },
                "default_cost": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "default_cost",
                    "help": "Summary default cost of stub or NSSA area.",
                    "category": "unitary"
                },
                "type": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "regular",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "nssa",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "stub",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "type",
                    "help": "Area type setting.",
                    "category": "unitary"
                },
                "id": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "id",
                    "help": "Area entry IP address.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "name": "area",
            "help": "OSPF area configuration.",
            "mkey": "id",
            "category": "table"
        },
        "distance_intra_area": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "distance_intra_area",
            "help": "Administrative intra-area route distance.",
            "category": "unitary"
        },
        "distance_external": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "distance_external",
            "help": "Administrative external route distance.",
            "category": "unitary"
        },
        "network": {
            "type": "list",
            "elements": "dict",
            "children": {
                "prefix": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "prefix",
                    "help": "Prefix.",
                    "category": "unitary"
                },
                "id": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "id",
                    "help": "Network entry ID.",
                    "category": "unitary"
                },
                "area": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "area",
                    "help": "Attach the network to area.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "name": "network",
            "help": "Enable OSPF on an IP network.",
            "mkey": "id",
            "category": "table"
        },
        "router_id": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "name": "router_id",
            "help": "Router ID.",
            "category": "unitary"
        },
        "default_information_metric_type": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "1",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "2",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "default_information_metric_type",
            "help": "Default information metric type.",
            "category": "unitary"
        },
        "database_overflow_time_to_recover": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "database_overflow_time_to_recover",
            "help": "Database overflow time to recover (sec).",
            "category": "unitary"
        },
        "log_neighbour_changes": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "log_neighbour_changes",
            "help": "Enable logging of OSPF neighbour's changes",
            "category": "unitary"
        },
        "rfc1583_compatible": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "rfc1583_compatible",
            "help": "Enable/disable RFC1583 compatibility.",
            "category": "unitary"
        },
        "default_information_metric": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "default_information_metric",
            "help": "Default information metric.",
            "category": "unitary"
        },
        "default_information_originate": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "always",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "default_information_originate",
            "help": "Enable/disable generation of default route.",
            "category": "unitary"
        },
        "passive_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "name",
                    "help": "Passive interface name.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "name": "passive_interface",
            "help": "Passive interface configuration.",
            "mkey": "name",
            "category": "table"
        },
        "distribute_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "access_list": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "access_list",
                    "help": "Access list name.",
                    "category": "unitary"
                },
                "protocol": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "connected",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "static",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "rip",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "bgp",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "isis",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "protocol",
                    "help": "Protocol type.",
                    "category": "unitary"
                },
                "id": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "id",
                    "help": "Distribute list entry ID.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "name": "distribute_list",
            "help": "Redistribute routes filter.",
            "mkey": "id",
            "category": "table"
        },
        "distance": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "distance",
            "help": "Administrative distance.",
            "category": "unitary"
        },
        "redistribute": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "status",
                    "help": "status",
                    "category": "unitary"
                },
                "name": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "name",
                    "help": "Redistribute name.",
                    "category": "unitary"
                },
                "metric_type": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "1",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "2",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "metric_type",
                    "help": "Metric type.",
                    "category": "unitary"
                },
                "tag": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "tag",
                    "help": "Tag value.",
                    "category": "unitary"
                },
                "routemap": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "routemap",
                    "help": "Route map name.",
                    "category": "unitary"
                },
                "metric": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "metric",
                    "help": "Redistribute metric setting.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "name": "redistribute",
            "help": "Redistribute configuration.",
            "mkey": "name",
            "category": "table"
        },
        "database_overflow": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "database_overflow",
            "help": "Enable/disable database overflow.",
            "category": "unitary"
        },
        "database_overflow_max_external_lsa": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "database_overflow_max_external_lsa",
            "help": "Database overflow maximum External LSAs.",
            "category": "unitary"
        },
        "name": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "name": "name",
            "help": "Vrf name.",
            "category": "unitary"
        },
        "spf_timers": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "name": "spf_timers",
            "help": "SPF calculation frequency.",
            "category": "unitary"
        },
        "distance_inter_area": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "distance_inter_area",
            "help": "Administrative inter-area route distance.",
            "category": "unitary"
        },
        "abr_type": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "cisco",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "ibm",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "shortcut",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "standard",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "abr_type",
            "help": "Area border router type.",
            "category": "unitary"
        },
        "interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "priority": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "priority",
                    "help": "Router priority.",
                    "category": "unitary"
                },
                "authentication_key": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "authentication_key",
                    "help": "Authentication key.",
                    "category": "unitary"
                },
                "name": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "name",
                    "help": "Interface entry name.",
                    "category": "unitary"
                },
                "dead_interval": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "dead_interval",
                    "help": "Dead interval. For fast-hello assign value 1.",
                    "category": "unitary"
                },
                "hello_multiplier": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "hello_multiplier",
                    "help": "Number of hello packets within dead interval.Valid only for fast-hello.",
                    "category": "unitary"
                },
                "bfd": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "bfd",
                    "help": "Bidirectional Forwarding Detection (BFD).",
                    "category": "unitary"
                },
                "transmit_delay": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "transmit_delay",
                    "help": "Link state transmit delay.",
                    "category": "unitary"
                },
                "mtu": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "mtu",
                    "help": "Interface MTU.",
                    "category": "unitary"
                },
                "retransmit_interval": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "retransmit_interval",
                    "help": "Time between retransmitting lost link state advertisements.",
                    "category": "unitary"
                },
                "authentication": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "text",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "md5",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "authentication",
                    "help": "Authentication type.",
                    "category": "unitary"
                },
                "cost": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "cost",
                    "help": "Cost of the interface.",
                    "category": "unitary"
                },
                "hello_interval": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "hello_interval",
                    "help": "Hello interval.",
                    "category": "unitary"
                },
                "md5_keys": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "id",
                            "help": "key-id (1-255).",
                            "category": "unitary"
                        },
                        "key": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "key",
                            "help": "md5-key.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "md5_keys",
                    "help": "OSPF md5 key configuration. Applicable only when authentication field is set to md5.",
                    "mkey": "id",
                    "category": "table"
                },
                "mtu_ignore": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "mtu_ignore",
                    "help": "Disable MTU mismatch detection on this interface.",
                    "category": "unitary"
                },
                "ucast_ttl": {
                    "revisions": {
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": False,
                        "v7.2.3": False,
                        "v7.2.4": False,
                        "v7.2.5": False,
                        "v7.4.0": False
                    },
                    "type": "integer",
                    "name": "ucast_ttl",
                    "help": "Unicast TTL.",
                    "category": "unitary"
                },
                "ttl": {
                    "revisions": {
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "ttl",
                    "help": "TTL.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "name": "interface",
            "help": "OSPF interface configuration.",
            "mkey": "name",
            "category": "table"
        },
        "vrf": {
            "type": "list",
            "elements": "dict",
            "children": {
                "summary_address": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "prefix": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "prefix",
                            "help": "Prefix.",
                            "category": "unitary"
                        },
                        "tag": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "tag",
                            "help": "Tag value.",
                            "category": "unitary"
                        },
                        "id": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "id",
                            "help": "Summary address entry ID.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "summary_address",
                    "help": "Aggregate address for redistributed routes.",
                    "mkey": "id",
                    "category": "table"
                },
                "area": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "nssa_translator_role": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "candidate",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "never",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "always",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "nssa_translator_role",
                            "help": "NSSA translator role type.",
                            "category": "unitary"
                        },
                        "virtual_link": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "dead_interval": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "integer",
                                    "name": "dead_interval",
                                    "help": "Dead interval.",
                                    "category": "unitary"
                                },
                                "hello_interval": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "integer",
                                    "name": "hello_interval",
                                    "help": "Hello interval.",
                                    "category": "unitary"
                                },
                                "name": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "name": "name",
                                    "help": "Virtual link entry name.",
                                    "category": "unitary"
                                },
                                "transmit_delay": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "integer",
                                    "name": "transmit_delay",
                                    "help": "Link state transmit delay.",
                                    "category": "unitary"
                                },
                                "retransmit_interval": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "integer",
                                    "name": "retransmit_interval",
                                    "help": "Time between retransmitting lost link state advertisements.",
                                    "category": "unitary"
                                },
                                "authentication": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "none",
                                            "revisions": {
                                                "v7.0.0": True,
                                                "v7.0.1": True,
                                                "v7.0.2": True,
                                                "v7.0.3": True,
                                                "v7.0.4": True,
                                                "v7.0.5": True,
                                                "v7.0.6": True,
                                                "v7.2.1": True,
                                                "v7.2.2": True,
                                                "v7.2.3": True,
                                                "v7.2.4": True,
                                                "v7.2.5": True,
                                                "v7.4.0": True
                                            }
                                        },
                                        {
                                            "value": "text",
                                            "revisions": {
                                                "v7.0.0": True,
                                                "v7.0.1": True,
                                                "v7.0.2": True,
                                                "v7.0.3": True,
                                                "v7.0.4": True,
                                                "v7.0.5": True,
                                                "v7.0.6": True,
                                                "v7.2.1": True,
                                                "v7.2.2": True,
                                                "v7.2.3": True,
                                                "v7.2.4": True,
                                                "v7.2.5": True,
                                                "v7.4.0": True
                                            }
                                        }
                                    ],
                                    "name": "authentication",
                                    "help": "Authentication type.",
                                    "category": "unitary"
                                },
                                "peer": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "name": "peer",
                                    "help": "Peer IP.",
                                    "category": "unitary"
                                },
                                "authentication_key": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "name": "authentication_key",
                                    "help": "Authentication key.",
                                    "category": "unitary"
                                }
                            },
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "name": "virtual_link",
                            "help": "OSPF virtual link configuration.",
                            "mkey": "name",
                            "category": "table"
                        },
                        "shortcut": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "default",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "shortcut",
                            "help": "Enable/disable shortcut option.",
                            "category": "unitary"
                        },
                        "stub_type": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "no_summary",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "summary",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "stub_type",
                            "help": "Stub summary setting.",
                            "category": "unitary"
                        },
                        "range": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "substitute": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "name": "substitute",
                                    "help": "Substitute prefix.",
                                    "category": "unitary"
                                },
                                "prefix": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "name": "prefix",
                                    "help": "Prefix.",
                                    "category": "unitary"
                                },
                                "substitute_status": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "enable",
                                            "revisions": {
                                                "v7.0.0": True,
                                                "v7.0.1": True,
                                                "v7.0.2": True,
                                                "v7.0.3": True,
                                                "v7.0.4": True,
                                                "v7.0.5": True,
                                                "v7.0.6": True,
                                                "v7.2.1": True,
                                                "v7.2.2": True,
                                                "v7.2.3": True,
                                                "v7.2.4": True,
                                                "v7.2.5": True,
                                                "v7.4.0": True
                                            }
                                        },
                                        {
                                            "value": "disable",
                                            "revisions": {
                                                "v7.0.0": True,
                                                "v7.0.1": True,
                                                "v7.0.2": True,
                                                "v7.0.3": True,
                                                "v7.0.4": True,
                                                "v7.0.5": True,
                                                "v7.0.6": True,
                                                "v7.2.1": True,
                                                "v7.2.2": True,
                                                "v7.2.3": True,
                                                "v7.2.4": True,
                                                "v7.2.5": True,
                                                "v7.4.0": True
                                            }
                                        }
                                    ],
                                    "name": "substitute_status",
                                    "help": "Enable/disable substitute status.",
                                    "category": "unitary"
                                },
                                "id": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "integer",
                                    "name": "id",
                                    "help": "Range entry ID.",
                                    "category": "unitary"
                                },
                                "advertise": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "disable",
                                            "revisions": {
                                                "v7.0.0": True,
                                                "v7.0.1": True,
                                                "v7.0.2": True,
                                                "v7.0.3": True,
                                                "v7.0.4": True,
                                                "v7.0.5": True,
                                                "v7.0.6": True,
                                                "v7.2.1": True,
                                                "v7.2.2": True,
                                                "v7.2.3": True,
                                                "v7.2.4": True,
                                                "v7.2.5": True,
                                                "v7.4.0": True
                                            }
                                        },
                                        {
                                            "value": "enable",
                                            "revisions": {
                                                "v7.0.0": True,
                                                "v7.0.1": True,
                                                "v7.0.2": True,
                                                "v7.0.3": True,
                                                "v7.0.4": True,
                                                "v7.0.5": True,
                                                "v7.0.6": True,
                                                "v7.2.1": True,
                                                "v7.2.2": True,
                                                "v7.2.3": True,
                                                "v7.2.4": True,
                                                "v7.2.5": True,
                                                "v7.4.0": True
                                            }
                                        }
                                    ],
                                    "name": "advertise",
                                    "help": "Enable/disable advertise status.",
                                    "category": "unitary"
                                }
                            },
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "name": "range",
                            "help": "OSPF area range configuration.",
                            "mkey": "id",
                            "category": "table"
                        },
                        "filter_list": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "direction": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "in",
                                            "revisions": {
                                                "v7.0.0": True,
                                                "v7.0.1": True,
                                                "v7.0.2": True,
                                                "v7.0.3": True,
                                                "v7.0.4": True,
                                                "v7.0.5": True,
                                                "v7.0.6": True,
                                                "v7.2.1": True,
                                                "v7.2.2": True,
                                                "v7.2.3": True,
                                                "v7.2.4": True,
                                                "v7.2.5": True,
                                                "v7.4.0": True
                                            }
                                        },
                                        {
                                            "value": "out",
                                            "revisions": {
                                                "v7.0.0": True,
                                                "v7.0.1": True,
                                                "v7.0.2": True,
                                                "v7.0.3": True,
                                                "v7.0.4": True,
                                                "v7.0.5": True,
                                                "v7.0.6": True,
                                                "v7.2.1": True,
                                                "v7.2.2": True,
                                                "v7.2.3": True,
                                                "v7.2.4": True,
                                                "v7.2.5": True,
                                                "v7.4.0": True
                                            }
                                        }
                                    ],
                                    "name": "direction",
                                    "help": "Direction.",
                                    "category": "unitary"
                                },
                                "list": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "name": "list",
                                    "help": "Access-list or prefix-list name.",
                                    "category": "unitary"
                                },
                                "id": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "integer",
                                    "name": "id",
                                    "help": "Filter list entry ID.",
                                    "category": "unitary"
                                }
                            },
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "name": "filter_list",
                            "help": "OSPF area filter-list configuration.",
                            "mkey": "id",
                            "category": "table"
                        },
                        "default_cost": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "default_cost",
                            "help": "Summary default cost of stub or NSSA area.",
                            "category": "unitary"
                        },
                        "type": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "regular",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "nssa",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "stub",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "type",
                            "help": "Area type setting.",
                            "category": "unitary"
                        },
                        "id": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "id",
                            "help": "Area entry IP address.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "area",
                    "help": "OSPF area configuration.",
                    "mkey": "id",
                    "category": "table"
                },
                "distance_intra_area": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "distance_intra_area",
                    "help": "Administrative intra-area route distance.",
                    "category": "unitary"
                },
                "distance_external": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "distance_external",
                    "help": "Administrative external route distance.",
                    "category": "unitary"
                },
                "network": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "prefix": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "prefix",
                            "help": "Prefix.",
                            "category": "unitary"
                        },
                        "id": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "id",
                            "help": "Network entry ID.",
                            "category": "unitary"
                        },
                        "area": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "area",
                            "help": "Attach the network to area.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "network",
                    "help": "Enable OSPF on an IP network.",
                    "mkey": "id",
                    "category": "table"
                },
                "router_id": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "router_id",
                    "help": "Router ID.",
                    "category": "unitary"
                },
                "default_information_metric_type": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "1",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "2",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "default_information_metric_type",
                    "help": "Default information metric type.",
                    "category": "unitary"
                },
                "database_overflow_time_to_recover": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "database_overflow_time_to_recover",
                    "help": "Database overflow time to recover (sec).",
                    "category": "unitary"
                },
                "log_neighbour_changes": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "log_neighbour_changes",
                    "help": "Enable logging of OSPF neighbour's changes",
                    "category": "unitary"
                },
                "rfc1583_compatible": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "rfc1583_compatible",
                    "help": "Enable/disable RFC1583 compatibility.",
                    "category": "unitary"
                },
                "default_information_metric": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "default_information_metric",
                    "help": "Default information metric.",
                    "category": "unitary"
                },
                "default_information_originate": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "always",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "default_information_originate",
                    "help": "Enable/disable generation of default route.",
                    "category": "unitary"
                },
                "passive_interface": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "name",
                            "help": "Passive interface name.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "passive_interface",
                    "help": "Passive interface configuration.",
                    "mkey": "name",
                    "category": "table"
                },
                "distribute_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "access_list": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "access_list",
                            "help": "Access list name.",
                            "category": "unitary"
                        },
                        "protocol": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "connected",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "static",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "rip",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "bgp",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "isis",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "protocol",
                            "help": "Protocol type.",
                            "category": "unitary"
                        },
                        "id": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "id",
                            "help": "Distribute list entry ID.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "distribute_list",
                    "help": "Redistribute routes filter.",
                    "mkey": "id",
                    "category": "table"
                },
                "distance": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "distance",
                    "help": "Administrative distance.",
                    "category": "unitary"
                },
                "redistribute": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "status": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "status",
                            "help": "status",
                            "category": "unitary"
                        },
                        "name": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "name",
                            "help": "Redistribute name.",
                            "category": "unitary"
                        },
                        "metric_type": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "1",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "2",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "metric_type",
                            "help": "Metric type.",
                            "category": "unitary"
                        },
                        "tag": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "tag",
                            "help": "Tag value.",
                            "category": "unitary"
                        },
                        "routemap": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "routemap",
                            "help": "Route map name.",
                            "category": "unitary"
                        },
                        "metric": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "metric",
                            "help": "Redistribute metric setting.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "redistribute",
                    "help": "Redistribute configuration.",
                    "mkey": "name",
                    "category": "table"
                },
                "database_overflow": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "database_overflow",
                    "help": "Enable/disable database overflow.",
                    "category": "unitary"
                },
                "database_overflow_max_external_lsa": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "database_overflow_max_external_lsa",
                    "help": "Database overflow maximum External LSAs.",
                    "category": "unitary"
                },
                "name": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "name",
                    "help": "Vrf name.",
                    "category": "unitary"
                },
                "spf_timers": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "spf_timers",
                    "help": "SPF calculation frequency.",
                    "category": "unitary"
                },
                "distance_inter_area": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "distance_inter_area",
                    "help": "Administrative inter-area route distance.",
                    "category": "unitary"
                },
                "abr_type": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "cisco",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "ibm",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "shortcut",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "standard",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "abr_type",
                    "help": "Area border router type.",
                    "category": "unitary"
                },
                "interface": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "priority": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "priority",
                            "help": "Router priority.",
                            "category": "unitary"
                        },
                        "authentication_key": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "authentication_key",
                            "help": "Authentication key.",
                            "category": "unitary"
                        },
                        "name": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "name": "name",
                            "help": "Interface entry name.",
                            "category": "unitary"
                        },
                        "dead_interval": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "dead_interval",
                            "help": "Dead interval. For fast-hello assign value 1.",
                            "category": "unitary"
                        },
                        "hello_multiplier": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "hello_multiplier",
                            "help": "Number of hello packets within dead interval.Valid only for fast-hello.",
                            "category": "unitary"
                        },
                        "transmit_delay": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "transmit_delay",
                            "help": "Link state transmit delay.",
                            "category": "unitary"
                        },
                        "mtu": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "mtu",
                            "help": "Interface MTU.",
                            "category": "unitary"
                        },
                        "retransmit_interval": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "retransmit_interval",
                            "help": "Time between retransmitting lost link state advertisements.",
                            "category": "unitary"
                        },
                        "authentication": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "none",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "text",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "md5",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "authentication",
                            "help": "Authentication type.",
                            "category": "unitary"
                        },
                        "cost": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "cost",
                            "help": "Cost of the interface.",
                            "category": "unitary"
                        },
                        "hello_interval": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "hello_interval",
                            "help": "Hello interval.",
                            "category": "unitary"
                        },
                        "md5_keys": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "id": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "integer",
                                    "name": "id",
                                    "help": "key-id (1-255).",
                                    "category": "unitary"
                                },
                                "key": {
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    },
                                    "type": "string",
                                    "name": "key",
                                    "help": "md5-key.",
                                    "category": "unitary"
                                }
                            },
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "name": "md5_keys",
                            "help": "OSPF md5 key configuration. Applicable only when authentication field is set to md5.",
                            "mkey": "id",
                            "category": "table"
                        },
                        "mtu_ignore": {
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True,
                                        "v7.0.1": True,
                                        "v7.0.2": True,
                                        "v7.0.3": True,
                                        "v7.0.4": True,
                                        "v7.0.5": True,
                                        "v7.0.6": True,
                                        "v7.2.1": True,
                                        "v7.2.2": True,
                                        "v7.2.3": True,
                                        "v7.2.4": True,
                                        "v7.2.5": True,
                                        "v7.4.0": True
                                    }
                                }
                            ],
                            "name": "mtu_ignore",
                            "help": "Disable MTU mismatch detection on this interface.",
                            "category": "unitary"
                        },
                        "ucast_ttl": {
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": False,
                                "v7.2.3": False,
                                "v7.2.4": False,
                                "v7.2.5": False,
                                "v7.4.0": False
                            },
                            "type": "integer",
                            "name": "ucast_ttl",
                            "help": "Unicast TTL.",
                            "category": "unitary"
                        },
                        "ttl": {
                            "revisions": {
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            },
                            "type": "integer",
                            "name": "ttl",
                            "help": "TTL.",
                            "category": "unitary"
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "name": "interface",
                    "help": "OSPF interface configuration.",
                    "mkey": "name",
                    "category": "table"
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "name": "vrf",
            "help": "Enable OSPF on VRF.",
            "mkey": "name",
            "category": "table"
        }
    },
    "name": "ospf",
    "help": "OSPF configuration.",
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
        "router_ospf": {
            "required": False, "type": "dict", "default": None,
            "options": {}
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
        is_error, has_changed, result, diff = fortiswitch_router(module.params, fos)
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
