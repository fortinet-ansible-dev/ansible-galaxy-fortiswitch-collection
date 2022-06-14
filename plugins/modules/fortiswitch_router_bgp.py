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
module: fortiswitch_router_bgp
short_description: BGP configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and bgp category.
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

    router_bgp:
        description:
            - BGP configuration.
        default: null
        type: dict
        suboptions:
            admin_distance:
                description:
                    - Administrative distance modifications.
                type: list
                elements: dict
                suboptions:
                    distance:
                        description:
                            - Administrative distance to apply (1 - 255).
                        type: int
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    neighbour_prefix:
                        description:
                            - Neighbor address prefix.
                        type: str
                    route_list:
                        description:
                            - Access list of routes to apply new distance to. Source router.access-list.name.
                        type: str
            aggregate_address:
                description:
                    - BGP aggregate address table.
                type: list
                elements: dict
                suboptions:
                    as_set:
                        description:
                            - Enable/disable generate AS set path information.
                        type: str
                        choices:
                            - enable
                            - disable
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    prefix:
                        description:
                            - Aggregate prefix.
                        type: str
                    summary_only:
                        description:
                            - Enable/disable filter more specific routes from updates.
                        type: str
                        choices:
                            - enable
                            - disable
            aggregate_address6:
                description:
                    - BGP IPv6 aggregate address table.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    prefix6:
                        description:
                            - Aggregate IPv6 prefix.
                        type: str
                    summary_only:
                        description:
                            - Enable/disable filter more specific routes from updates.
                        type: str
                        choices:
                            - enable
                            - disable
            always_compare_med:
                description:
                    - Enable/disable always compare MED.
                type: str
                choices:
                    - enable
                    - disable
            as:
                description:
                    - Router AS number.
                type: int
            bestpath_as_path_ignore:
                description:
                    - Enable/disable ignore AS path.
                type: str
                choices:
                    - enable
                    - disable
            bestpath_aspath_multipath_relax:
                description:
                    - Allow load sharing across routes that have different AS paths (but same length).
                type: str
                choices:
                    - disable
                    - enable
            bestpath_cmp_confed_aspath:
                description:
                    - Enable/disable compare federation AS path length.
                type: str
                choices:
                    - enable
                    - disable
            bestpath_cmp_routerid:
                description:
                    - Enable/disable compare router ID for identical EBGP paths.
                type: str
                choices:
                    - enable
                    - disable
            bestpath_med_confed:
                description:
                    - Enable/disable compare MED among confederation paths.
                type: str
                choices:
                    - enable
                    - disable
            bestpath_med_missing_as_worst:
                description:
                    - Enable/disable treat missing MED as least preferred.
                type: str
                choices:
                    - enable
                    - disable
            client_to_client_reflection:
                description:
                    - Enable/disable client-to-client route reflection.
                type: str
                choices:
                    - enable
                    - disable
            cluster_id:
                description:
                    - Route reflector cluster ID.
                type: str
            confederation_identifier:
                description:
                    - Confederation identifier.
                type: int
            confederation_peers:
                description:
                    - Confederation peers.
                type: list
                elements: dict
                suboptions:
                    peer:
                        description:
                            - Peer ID.
                        required: true
                        type: str
            dampening:
                description:
                    - Enable/disable route-flap dampening.
                type: str
                choices:
                    - enable
                    - disable
            dampening_max_suppress_time:
                description:
                    - Maximum minutes a route can be suppressed.
                type: int
            dampening_reachability_half_life:
                description:
                    - Reachability half-life time for penalty (minutes).
                type: int
            dampening_reuse:
                description:
                    - Threshold to unsuppress routes.
                type: int
            dampening_suppress:
                description:
                    - Threshold to suppress routes.
                type: int
            default_local_preference:
                description:
                    - Default local preference.
                type: int
            deterministic_med:
                description:
                    - Enable/disable enforce deterministic comparison of MED.
                type: str
                choices:
                    - enable
                    - disable
            distance_external:
                description:
                    - Distance for routes external to the AS.
                type: int
            distance_internal:
                description:
                    - Distance for routes internal to the AS.
                type: int
            distance_local:
                description:
                    - Distance for routes local to the AS.
                type: int
            enforce_first_as:
                description:
                    - Enable/disable enforce first AS for EBGP routes.
                type: str
                choices:
                    - enable
                    - disable
            fast_external_failover:
                description:
                    - Enable/disable reset peer BGP session if link goes down.
                type: str
                choices:
                    - enable
                    - disable
            graceful_stalepath_time:
                description:
                    - Time to hold stale paths of restarting neighbour(sec).
                type: int
            holdtime_timer:
                description:
                    - Number of seconds to mark peer as dead.
                type: int
            keepalive_timer:
                description:
                    - Frequency to send keepalive requests.
                type: int
            log_neighbour_changes:
                description:
                    - Enable logging of BGP neighbour"s changes
                type: str
                choices:
                    - enable
                    - disable
            maximum_paths_ebgp:
                description:
                    - Maximum paths for ebgp ecmp.
                type: int
            maximum_paths_ibgp:
                description:
                    - Maximum paths for ibgp ecmp.
                type: int
            neighbor:
                description:
                    - BGP neighbor table.
                type: list
                elements: dict
                suboptions:
                    activate:
                        description:
                            - Enable/disable address family IPv4 for this neighbor.
                        type: str
                        choices:
                            - enable
                            - disable
                    activate6:
                        description:
                            - Enable/disable address family IPv6 for this neighbor.
                        type: str
                        choices:
                            - enable
                            - disable
                    advertisement_interval:
                        description:
                            - Minimum interval (seconds) between sending updates.
                        type: int
                    allowas_in:
                        description:
                            - IPv4 The maximum number of occurrence of my AS number allowed.
                        type: int
                    allowas_in_enable:
                        description:
                            - Enable/disable IPv4 Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - enable
                            - disable
                    allowas_in_enable6:
                        description:
                            - Enable/disable IPv6 Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - enable
                            - disable
                    allowas_in6:
                        description:
                            - IPv6 The maximum number of occurrence of my AS number allowed.
                        type: int
                    as_override:
                        description:
                            - Enable/disable replace peer AS with own AS for IPv4.
                        type: str
                        choices:
                            - enable
                            - disable
                    as_override6:
                        description:
                            - Enable/disable replace peer AS with own AS for IPv6.
                        type: str
                        choices:
                            - enable
                            - disable
                    attribute_unchanged:
                        description:
                            - IPv4 List of attributes that should be unchanged.
                        type: str
                        choices:
                            - as-path
                            - med
                            - next-hop
                    attribute_unchanged6:
                        description:
                            - IPv6 List of attributes that should be unchanged.
                        type: str
                        choices:
                            - as-path
                            - med
                            - next-hop
                    bfd:
                        description:
                            - Enable/disable BFD for this neighbor.
                        type: str
                        choices:
                            - enable
                            - disable
                    bfd_session_mode:
                        description:
                            - Single or multihop BFD session to this neighbor.
                        type: str
                        choices:
                            - automatic
                            - multihop
                            - singlehop
                    capability_default_originate:
                        description:
                            - Enable/disable advertise default IPv4 route to this neighbor.
                        type: str
                        choices:
                            - enable
                            - disable
                    capability_default_originate6:
                        description:
                            - Enable/disable advertise default IPv6 route to this neighbor.
                        type: str
                        choices:
                            - enable
                            - disable
                    capability_dynamic:
                        description:
                            - Enable/disable advertise dynamic capability to this neighbor.
                        type: str
                        choices:
                            - enable
                            - disable
                    capability_orf:
                        description:
                            - Accept/Send IPv4 ORF lists to/from this neighbor.
                        type: str
                        choices:
                            - none
                            - receive
                            - send
                            - both
                    capability_orf6:
                        description:
                            - Accept/Send IPv6 ORF lists to/from this neighbor.
                        type: str
                        choices:
                            - none
                            - receive
                            - send
                            - both
                    connect_timer:
                        description:
                            - Interval (seconds) for connect timer.
                        type: int
                    default_originate_routemap:
                        description:
                            - Route map to specify criteria to originate IPv4 default. Source router.route-map.name.
                        type: str
                    default_originate_routemap6:
                        description:
                            - Route map to specify criteria to originate IPv6 default. Source router.route-map.name.
                        type: str
                    description:
                        description:
                            - Description.
                        type: str
                    distribute_list_in:
                        description:
                            - Filter for IPv4 updates from this neighbor. Source router.access-list.name.
                        type: str
                    distribute_list_in6:
                        description:
                            - Filter for IPv6 updates from this neighbor. Source router.access-list6.name.
                        type: str
                    distribute_list_out:
                        description:
                            - Filter for IPv4 updates to this neighbor. Source router.access-list.name.
                        type: str
                    distribute_list_out6:
                        description:
                            - Filter for IPv6 updates to this neighbor. Source router.access-list6.name.
                        type: str
                    dont_capability_negotiate:
                        description:
                            - Don"t negotiate capabilities with this neighbor
                        type: str
                        choices:
                            - enable
                            - disable
                    ebgp_enforce_multihop:
                        description:
                            - Enable/disable allow multi-hop next-hops from EBGP neighbors.
                        type: str
                        choices:
                            - enable
                            - disable
                    ebgp_multihop_ttl:
                        description:
                            - EBGP multihop TTL for this peer.
                        type: int
                    ebgp_ttl_security_hops:
                        description:
                            - Specify the maximum number of hops to the EBGP peer.
                        type: int
                    filter_list_in:
                        description:
                            - BGP aspath filter for IPv4 inbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_in6:
                        description:
                            - BGP filter for IPv6 inbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_out:
                        description:
                            - BGP aspath filter for IPv4 outbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_out6:
                        description:
                            - BGP filter for IPv6 outbound routes. Source router.aspath-list.name.
                        type: str
                    holdtime_timer:
                        description:
                            - Interval (seconds) before peer considered dead.
                        type: int
                    interface:
                        description:
                            - Interface. Source system.interface.name.
                        type: str
                    ip:
                        description:
                            - IP/IPv6 address of neighbor.
                        required: true
                        type: str
                    keep_alive_timer:
                        description:
                            - Keepalive timer interval (seconds).
                        type: int
                    maximum_prefix:
                        description:
                            - Maximum number of IPv4 prefixes to accept from this peer.
                        type: int
                    maximum_prefix_threshold:
                        description:
                            - Maximum IPv4 prefix threshold value (1-100 percent).
                        type: int
                    maximum_prefix_threshold6:
                        description:
                            - Maximum IPv6 prefix threshold value (1-100 percent)
                        type: int
                    maximum_prefix_warning_only:
                        description:
                            - Enable/disable IPv4 Only give warning message when threshold is exceeded.
                        type: str
                        choices:
                            - enable
                            - disable
                    maximum_prefix_warning_only6:
                        description:
                            - Enable/disable IPv6 Only give warning message when threshold is exceeded.
                        type: str
                        choices:
                            - enable
                            - disable
                    maximum_prefix6:
                        description:
                            - Maximum number of IPv6 prefixes to accept from this peer.
                        type: int
                    next_hop_self:
                        description:
                            - Enable/disable IPv4 next-hop calculation for this neighbor.
                        type: str
                        choices:
                            - enable
                            - disable
                    next_hop_self6:
                        description:
                            - Enable/disable IPv6 next-hop calculation for this neighbor.
                        type: str
                        choices:
                            - enable
                            - disable
                    override_capability:
                        description:
                            - Enable/disable override result of capability negotiation.
                        type: str
                        choices:
                            - enable
                            - disable
                    passive:
                        description:
                            - Enable/disable sending of open messages to this neighbor.
                        type: str
                        choices:
                            - enable
                            - disable
                    password:
                        description:
                            - Password used in MD5 authentication.
                        type: str
                    prefix_list_in:
                        description:
                            - IPv4 Inbound filter for updates from this neighbor. Source router.prefix-list.name.
                        type: str
                    prefix_list_in6:
                        description:
                            - IPv6 Inbound filter for updates from this neighbor. Source router.prefix-list6.name.
                        type: str
                    prefix_list_out:
                        description:
                            - IPv4 Outbound filter for updates to this neighbor. Source router.prefix-list.name.
                        type: str
                    prefix_list_out6:
                        description:
                            - IPv6 Outbound filter for updates to this neighbor. Source router.prefix-list6.name.
                        type: str
                    remote_as:
                        description:
                            - AS number of neighbor.
                        type: int
                    remove_private_as:
                        description:
                            - Enable/disable remove private AS number from IPv4 outbound updates.
                        type: str
                        choices:
                            - enable
                            - disable
                    remove_private_as6:
                        description:
                            - Enable/disable remove private AS number from IPv6 outbound updates.
                        type: str
                        choices:
                            - enable
                            - disable
                    route_map_in:
                        description:
                            - IPv4 Inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_in6:
                        description:
                            - IPv6 Inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out:
                        description:
                            - IPv4 outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out6:
                        description:
                            - IPv6 Outbound route map filter. Source router.route-map.name.
                        type: str
                    route_reflector_client:
                        description:
                            - Enable/disable IPv4 AS route reflector client.
                        type: str
                        choices:
                            - enable
                            - disable
                    route_reflector_client6:
                        description:
                            - Enable/disable IPv6 AS route reflector client.
                        type: str
                        choices:
                            - enable
                            - disable
                    route_server_client:
                        description:
                            - Enable/disable IPv4 AS route server client.
                        type: str
                        choices:
                            - enable
                            - disable
                    route_server_client6:
                        description:
                            - Enable/disable IPv6 AS route server client.
                        type: str
                        choices:
                            - enable
                            - disable
                    send_community:
                        description:
                            - IPv4 Send community attribute to neighbor.
                        type: str
                        choices:
                            - standard
                            - extended
                            - both
                            - disable
                    send_community6:
                        description:
                            - IPv6 Send community attribute to neighbor.
                        type: str
                        choices:
                            - standard
                            - extended
                            - both
                            - disable
                    shutdown:
                        description:
                            - Enable/disable shutdown this neighbor.
                        type: str
                        choices:
                            - enable
                            - disable
                    soft_reconfiguration:
                        description:
                            - Enable/disable allow IPv4 inbound soft reconfiguration.
                        type: str
                        choices:
                            - enable
                            - disable
                    soft_reconfiguration6:
                        description:
                            - Enable/disable allow IPv6 inbound soft reconfiguration.
                        type: str
                        choices:
                            - enable
                            - disable
                    strict_capability_match:
                        description:
                            - Enable/disable strict capability matching.
                        type: str
                        choices:
                            - enable
                            - disable
                    unsuppress_map:
                        description:
                            - IPv4 Route map to selectively unsuppress suppressed routes. Source router.route-map.name.
                        type: str
                    unsuppress_map6:
                        description:
                            - IPv6 Route map to selectively unsuppress suppressed routes. Source router.route-map.name.
                        type: str
                    update_source:
                        description:
                            - Interface to use as source IP/IPv6 address of TCP connections. Source system.interface.name.
                        type: str
                    weight:
                        description:
                            - Neighbor weight.
                        type: int
            network:
                description:
                    - BGP network table.
                type: list
                elements: dict
                suboptions:
                    backdoor:
                        description:
                            - Enable/disable route as backdoor.
                        type: str
                        choices:
                            - enable
                            - disable
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    prefix:
                        description:
                            - Network prefix.
                        type: str
                    route_map:
                        description:
                            - Route map to modify generated route. Source router.route-map.name.
                        type: str
            network6:
                description:
                    - BGP IPv6 network table.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    prefix6:
                        description:
                            - Network IPv6 prefix.
                        type: str
                    route_map:
                        description:
                            - Route map to modify generated route. Source router.route-map.name.
                        type: str
            redistribute:
                description:
                    - BGP IPv4 redistribute table.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Redistribute protocol name.
                        required: true
                        type: str
                    route_map:
                        description:
                            - Route map name. Source router.route-map.name.
                        type: str
                    status:
                        description:
                            - Status
                        type: str
                        choices:
                            - enable
                            - disable
            redistribute6:
                description:
                    - BGP IPv6 redistribute table.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Distribute list entry name.
                        required: true
                        type: str
                    route_map:
                        description:
                            - Route map name. Source router.route-map.name.
                        type: str
                    status:
                        description:
                            - Status
                        type: str
                        choices:
                            - enable
                            - disable
            router_id:
                description:
                    - Router ID.
                type: str
            scan_time:
                description:
                    - Background scanner interval (seconds).
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
  - name: BGP configuration.
    fortiswitch_router_bgp:
      router_bgp:
        admin_distance:
         -
            distance: "4"
            id:  "5"
            neighbour_prefix: "<your_own_value>"
            route_list: "<your_own_value> (source router.access-list.name)"
        aggregate_address:
         -
            as_set: "enable"
            id:  "10"
            prefix: "<your_own_value>"
            summary_only: "enable"
        aggregate_address6:
         -
            id:  "14"
            prefix6: "<your_own_value>"
            summary_only: "enable"
        always_compare_med: "enable"
        as: "18"
        bestpath_as_path_ignore: "enable"
        bestpath_aspath_multipath_relax: "disable"
        bestpath_cmp_confed_aspath: "enable"
        bestpath_cmp_routerid: "enable"
        bestpath_med_confed: "enable"
        bestpath_med_missing_as_worst: "enable"
        client_to_client_reflection: "enable"
        cluster_id: "<your_own_value>"
        confederation_identifier: "27"
        confederation_peers:
         -
            peer: "<your_own_value>"
        dampening: "enable"
        dampening_max_suppress_time: "31"
        dampening_reachability_half_life: "32"
        dampening_reuse: "33"
        dampening_suppress: "34"
        default_local_preference: "35"
        deterministic_med: "enable"
        distance_external: "37"
        distance_internal: "38"
        distance_local: "39"
        enforce_first_as: "enable"
        fast_external_failover: "enable"
        graceful_stalepath_time: "42"
        holdtime_timer: "43"
        keepalive_timer: "44"
        log_neighbour_changes: "enable"
        maximum_paths_ebgp: "46"
        maximum_paths_ibgp: "47"
        neighbor:
         -
            activate: "enable"
            activate6: "enable"
            advertisement_interval: "51"
            allowas_in: "52"
            allowas_in_enable: "enable"
            allowas_in_enable6: "enable"
            allowas_in6: "55"
            as_override: "enable"
            as_override6: "enable"
            attribute_unchanged: "as-path"
            attribute_unchanged6: "as-path"
            bfd: "enable"
            bfd_session_mode: "automatic"
            capability_default_originate: "enable"
            capability_default_originate6: "enable"
            capability_dynamic: "enable"
            capability_orf: "none"
            capability_orf6: "none"
            connect_timer: "67"
            default_originate_routemap: "<your_own_value> (source router.route-map.name)"
            default_originate_routemap6: "<your_own_value> (source router.route-map.name)"
            description: "<your_own_value>"
            distribute_list_in: "<your_own_value> (source router.access-list.name)"
            distribute_list_in6: "<your_own_value> (source router.access-list6.name)"
            distribute_list_out: "<your_own_value> (source router.access-list.name)"
            distribute_list_out6: "<your_own_value> (source router.access-list6.name)"
            dont_capability_negotiate: "enable"
            ebgp_enforce_multihop: "enable"
            ebgp_multihop_ttl: "77"
            ebgp_ttl_security_hops: "78"
            filter_list_in: "<your_own_value> (source router.aspath-list.name)"
            filter_list_in6: "<your_own_value> (source router.aspath-list.name)"
            filter_list_out: "<your_own_value> (source router.aspath-list.name)"
            filter_list_out6: "<your_own_value> (source router.aspath-list.name)"
            holdtime_timer: "83"
            interface: "<your_own_value> (source system.interface.name)"
            ip: "<your_own_value>"
            keep_alive_timer: "86"
            maximum_prefix: "87"
            maximum_prefix_threshold: "88"
            maximum_prefix_threshold6: "89"
            maximum_prefix_warning_only: "enable"
            maximum_prefix_warning_only6: "enable"
            maximum_prefix6: "92"
            next_hop_self: "enable"
            next_hop_self6: "enable"
            override_capability: "enable"
            passive: "enable"
            password: "<your_own_value>"
            prefix_list_in: "<your_own_value> (source router.prefix-list.name)"
            prefix_list_in6: "<your_own_value> (source router.prefix-list6.name)"
            prefix_list_out: "<your_own_value> (source router.prefix-list.name)"
            prefix_list_out6: "<your_own_value> (source router.prefix-list6.name)"
            remote_as: "102"
            remove_private_as: "enable"
            remove_private_as6: "enable"
            route_map_in: "<your_own_value> (source router.route-map.name)"
            route_map_in6: "<your_own_value> (source router.route-map.name)"
            route_map_out: "<your_own_value> (source router.route-map.name)"
            route_map_out6: "<your_own_value> (source router.route-map.name)"
            route_reflector_client: "enable"
            route_reflector_client6: "enable"
            route_server_client: "enable"
            route_server_client6: "enable"
            send_community: "standard"
            send_community6: "standard"
            shutdown: "enable"
            soft_reconfiguration: "enable"
            soft_reconfiguration6: "enable"
            strict_capability_match: "enable"
            unsuppress_map: "<your_own_value> (source router.route-map.name)"
            unsuppress_map6: "<your_own_value> (source router.route-map.name)"
            update_source: "<your_own_value> (source system.interface.name)"
            weight: "122"
        network:
         -
            backdoor: "enable"
            id:  "125"
            prefix: "<your_own_value>"
            route_map: "<your_own_value> (source router.route-map.name)"
        network6:
         -
            id:  "129"
            prefix6: "<your_own_value>"
            route_map: "<your_own_value> (source router.route-map.name)"
        redistribute:
         -
            name: "default_name_133"
            route_map: "<your_own_value> (source router.route-map.name)"
            status: "enable"
        redistribute6:
         -
            name: "default_name_137"
            route_map: "<your_own_value> (source router.route-map.name)"
            status: "enable"
        router_id: "<your_own_value>"
        scan_time: "141"

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
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.secret_field import is_secret_field


def filter_router_bgp_data(json):
    option_list = ['admin_distance', 'aggregate_address', 'aggregate_address6',
                   'always_compare_med', 'as', 'bestpath_as_path_ignore',
                   'bestpath_aspath_multipath_relax', 'bestpath_cmp_confed_aspath', 'bestpath_cmp_routerid',
                   'bestpath_med_confed', 'bestpath_med_missing_as_worst', 'client_to_client_reflection',
                   'cluster_id', 'confederation_identifier', 'confederation_peers',
                   'dampening', 'dampening_max_suppress_time', 'dampening_reachability_half_life',
                   'dampening_reuse', 'dampening_suppress', 'default_local_preference',
                   'deterministic_med', 'distance_external', 'distance_internal',
                   'distance_local', 'enforce_first_as', 'fast_external_failover',
                   'graceful_stalepath_time', 'holdtime_timer', 'keepalive_timer',
                   'log_neighbour_changes', 'maximum_paths_ebgp', 'maximum_paths_ibgp',
                   'neighbor', 'network', 'network6',
                   'redistribute', 'redistribute6', 'router_id',
                   'scan_time']
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


def router_bgp(data, fos):
    router_bgp_data = data['router_bgp']
    filtered_data = underscore_to_hyphen(filter_router_bgp_data(router_bgp_data))

    return fos.set('router',
                   'bgp',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_router(data, fos):

    fos.do_member_operation('router_bgp')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['router_bgp']:
        resp = router_bgp(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('router_bgp'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp


versioned_schema = {
    "type": "dict",
    "children": {
        "confederation_peers": {
            "elements": "dict",
            "type": "list",
            "children": {
                "peer": {
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
        "dampening_max_suppress_time": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "distance_internal": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "dampening_reuse": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "dampening_reachability_half_life": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "graceful_stalepath_time": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "admin_distance": {
            "elements": "dict",
            "type": "list",
            "children": {
                "neighbour_prefix": {
                    "type": "string",
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
                "route_list": {
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
        "aggregate_address6": {
            "elements": "dict",
            "type": "list",
            "children": {
                "summary_only": {
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
                "prefix6": {
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
        "as": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "cluster_id": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "maximum_paths_ebgp": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "bestpath_aspath_multipath_relax": {
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
        "client_to_client_reflection": {
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
        "distance_local": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "dampening": {
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
        "network": {
            "elements": "dict",
            "type": "list",
            "children": {
                "backdoor": {
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
                "route_map": {
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
        "bestpath_med_confed": {
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
        "dampening_suppress": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "aggregate_address": {
            "elements": "dict",
            "type": "list",
            "children": {
                "summary_only": {
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
                "as_set": {
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
        "bestpath_cmp_confed_aspath": {
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
        "scan_time": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "fast_external_failover": {
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
        "bestpath_med_missing_as_worst": {
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
        "router_id": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "default_local_preference": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "bestpath_as_path_ignore": {
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
        "always_compare_med": {
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
        "confederation_identifier": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "maximum_paths_ibgp": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "network6": {
            "elements": "dict",
            "type": "list",
            "children": {
                "route_map": {
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
                "prefix6": {
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
        "keepalive_timer": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "redistribute": {
            "elements": "dict",
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
                "route_map": {
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
                }
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "deterministic_med": {
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
        "enforce_first_as": {
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
        "bestpath_cmp_routerid": {
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
        "redistribute6": {
            "elements": "dict",
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
                "route_map": {
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
                }
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "neighbor": {
            "elements": "dict",
            "type": "list",
            "children": {
                "soft_reconfiguration6": {
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
                "activate": {
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
                "route_reflector_client": {
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
                "weight": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "ebgp_multihop_ttl": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "prefix_list_in6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "prefix_list_out": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "default_originate_routemap6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "route_map_out6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "distribute_list_out": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "shutdown": {
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
                "unsuppress_map": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "strict_capability_match": {
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
                "remove_private_as": {
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
                "as_override": {
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
                "allowas_in_enable": {
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
                "description": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "route_reflector_client6": {
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
                "filter_list_out6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "filter_list_out": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "remote_as": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "capability_orf6": {
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
                            "value": "receive",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "send",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "both",
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
                "override_capability": {
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
                "route_server_client6": {
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
                "allowas_in": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "passive": {
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
                "allowas_in6": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "advertisement_interval": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "prefix_list_out6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "activate6": {
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
                "filter_list_in6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "capability_orf": {
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
                            "value": "receive",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "send",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "both",
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
                "distribute_list_in6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "maximum_prefix": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "soft_reconfiguration": {
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
                "dont_capability_negotiate": {
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
                "as_override6": {
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
                "update_source": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "maximum_prefix_warning_only": {
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
                "next_hop_self6": {
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
                "remove_private_as6": {
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
                "ebgp_ttl_security_hops": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "allowas_in_enable6": {
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
                "capability_dynamic": {
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
                "filter_list_in": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "capability_default_originate6": {
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
                "maximum_prefix6": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "route_map_in6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "route_server_client": {
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
                "attribute_unchanged": {
                    "type": "string",
                    "options": [
                        {
                            "value": "as-path",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "med",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "next-hop",
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
                "capability_default_originate": {
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
                "maximum_prefix_threshold6": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "bfd_session_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "automatic",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "multihop",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "singlehop",
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
                "interface": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "next_hop_self": {
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
                "password": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "route_map_in": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "ebgp_enforce_multihop": {
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
                "maximum_prefix_warning_only6": {
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
                "attribute_unchanged6": {
                    "type": "string",
                    "options": [
                        {
                            "value": "as-path",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "med",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "next-hop",
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
                "holdtime_timer": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "distribute_list_out6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "distribute_list_in": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "connect_timer": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "send_community6": {
                    "type": "string",
                    "options": [
                        {
                            "value": "standard",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "extended",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "both",
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
                "route_map_out": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "maximum_prefix_threshold": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "send_community": {
                    "type": "string",
                    "options": [
                        {
                            "value": "standard",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "extended",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "both",
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
                "prefix_list_in": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "keep_alive_timer": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "default_originate_routemap": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "unsuppress_map6": {
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
        "holdtime_timer": {
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
        "enable_log": {"required": False, "type": "bool", "default": False},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "router_bgp": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["router_bgp"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["router_bgp"]['options'][attribute_name]['required'] = True
        if is_secret_field(attribute_name):
            fields["router_bgp"]['options'][attribute_name]['no_log'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "router_bgp")

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
