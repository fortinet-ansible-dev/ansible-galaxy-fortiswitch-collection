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
                        type: int
                    neighbour_prefix:
                        description:
                            - Neighbor address prefix.
                        type: str
                    route_list:
                        description:
                            - Access list of routes to apply new distance to.
                        type: str
            admin_distance6:
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
                        type: int
                    neighbour_prefix6:
                        description:
                            - Neighbor IPV6 prefix.
                        type: str
                    route6_list:
                        description:
                            - Access list of routes to apply new distance to.
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
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - ID.
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
                            - 'enable'
                            - 'disable'
            aggregate_address6:
                description:
                    - BGP IPv6 aggregate address table.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID.
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
                            - 'enable'
                            - 'disable'
            always_compare_med:
                description:
                    - Enable/disable always compare MED.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            as:
                description:
                    - Router AS number.
                type: int
            bestpath_as_path_ignore:
                description:
                    - Enable/disable ignore AS path.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bestpath_aspath_multipath_relax:
                description:
                    - Allow load sharing across routes that have different AS paths (but same length).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            bestpath_cmp_confed_aspath:
                description:
                    - Enable/disable compare federation AS path length.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bestpath_cmp_routerid:
                description:
                    - Enable/disable compare router ID for identical EBGP paths.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bestpath_med_confed:
                description:
                    - Enable/disable compare MED among confederation paths.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bestpath_med_missing_as_worst:
                description:
                    - Enable/disable treat missing MED as least preferred.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            client_to_client_reflection:
                description:
                    - Enable/disable client-to-client route reflection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
                        type: str
            dampening:
                description:
                    - Enable/disable route-flap dampening.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
                    - 'enable'
                    - 'disable'
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
            ebgp_requires_policy:
                description:
                    - Enable/disable require in and out policy for eBGP peers (RFC8212).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            enforce_first_as:
                description:
                    - Enable/disable enforce first AS for EBGP routes.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fast_external_failover:
                description:
                    - Enable/disable reset peer BGP session if link goes down.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
                    - 'enable'
                    - 'disable'
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
                            - 'enable'
                            - 'disable'
                    activate6:
                        description:
                            - Enable/disable address family IPv6 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate_evpn:
                        description:
                            - Enable/disable address family evpn for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    advertisement_interval:
                        description:
                            - Minimum interval (seconds) between sending updates.
                        type: int
                    allowas_in:
                        description:
                            - IPv4 The maximum number of occurrence of my AS number allowed.
                        type: int
                    allowas_in6:
                        description:
                            - IPv6 The maximum number of occurrence of my AS number allowed.
                        type: int
                    allowas_in_enable:
                        description:
                            - Enable/disable IPv4 Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable6:
                        description:
                            - Enable/disable IPv6 Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable_evpn:
                        description:
                            - Enable/disable EVPN Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    as_override:
                        description:
                            - Enable/disable replace peer AS with own AS for IPv4.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    as_override6:
                        description:
                            - Enable/disable replace peer AS with own AS for IPv6.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    attribute_unchanged:
                        description:
                            - IPv4 List of attributes that should be unchanged.
                        type: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    attribute_unchanged6:
                        description:
                            - IPv6 List of attributes that should be unchanged.
                        type: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    attribute_unchanged_evpn:
                        description:
                            - EVPN List of attributes that should be unchanged.
                        type: str
                        choices:
                            - 'as-path'
                            - 'med'
                    bfd:
                        description:
                            - Enable/disable BFD for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bfd_session_mode:
                        description:
                            - Single or multihop BFD session to this neighbor.
                        type: str
                        choices:
                            - 'automatic'
                            - 'multihop'
                            - 'singlehop'
                    capability_default_originate:
                        description:
                            - Enable/disable advertise default IPv4 route to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_default_originate6:
                        description:
                            - Enable/disable advertise default IPv6 route to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_dynamic:
                        description:
                            - Enable/disable advertise dynamic capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_extended_nexthop:
                        description:
                            - Enable/disable extended nexthop capability.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_orf:
                        description:
                            - Accept/Send IPv4 ORF lists to/from this neighbor.
                        type: str
                        choices:
                            - 'none'
                            - 'receive'
                            - 'send'
                            - 'both'
                    capability_orf6:
                        description:
                            - Accept/Send IPv6 ORF lists to/from this neighbor.
                        type: str
                        choices:
                            - 'none'
                            - 'receive'
                            - 'send'
                            - 'both'
                    connect_timer:
                        description:
                            - Interval (seconds) for connect timer.
                        type: int
                    default_originate_routemap:
                        description:
                            - Route map to specify criteria to originate IPv4 default.
                        type: str
                    default_originate_routemap6:
                        description:
                            - Route map to specify criteria to originate IPv6 default.
                        type: str
                    description:
                        description:
                            - Description.
                        type: str
                    distribute_list_in:
                        description:
                            - Filter for IPv4 updates from this neighbor.
                        type: str
                    distribute_list_in6:
                        description:
                            - Filter for IPv6 updates from this neighbor.
                        type: str
                    distribute_list_out:
                        description:
                            - Filter for IPv4 updates to this neighbor.
                        type: str
                    distribute_list_out6:
                        description:
                            - Filter for IPv6 updates to this neighbor.
                        type: str
                    dont_capability_negotiate:
                        description:
                            - Don"t negotiate capabilities with this neighbor
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ebgp_enforce_multihop:
                        description:
                            - Enable/disable allow multi-hop next-hops from EBGP neighbors.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ebgp_multihop_ttl:
                        description:
                            - EBGP multihop TTL for this peer.
                        type: int
                    ebgp_ttl_security_hops:
                        description:
                            - Specify the maximum number of hops to the EBGP peer.
                        type: int
                    enforce_first_as:
                        description:
                            - Enable/disable  - Enable to enforce first AS for all(IPV4/IPV6) EBGP routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    filter_list_in:
                        description:
                            - BGP aspath filter for IPv4 inbound routes.
                        type: str
                    filter_list_in6:
                        description:
                            - BGP filter for IPv6 inbound routes.
                        type: str
                    filter_list_out:
                        description:
                            - BGP aspath filter for IPv4 outbound routes.
                        type: str
                    filter_list_out6:
                        description:
                            - BGP filter for IPv6 outbound routes.
                        type: str
                    holdtime_timer:
                        description:
                            - Interval (seconds) before peer considered dead.
                        type: int
                    interface:
                        description:
                            - Interface.
                        type: str
                    ip:
                        description:
                            - IP/IPv6 address of neighbor.
                        type: str
                    keep_alive_timer:
                        description:
                            - Keepalive timer interval (seconds).
                        type: int
                    maximum_prefix:
                        description:
                            - Maximum number of IPv4 prefixes to accept from this peer.
                        type: int
                    maximum_prefix6:
                        description:
                            - Maximum number of IPv6 prefixes to accept from this peer.
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
                            - 'enable'
                            - 'disable'
                    maximum_prefix_warning_only6:
                        description:
                            - Enable/disable IPv6 Only give warning message when threshold is exceeded.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self:
                        description:
                            - Enable/disable IPv4 next-hop calculation for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self6:
                        description:
                            - Enable/disable IPv6 next-hop calculation for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_capability:
                        description:
                            - Enable/disable override result of capability negotiation.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    passive:
                        description:
                            - Enable/disable sending of open messages to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    password:
                        description:
                            - Password used in MD5 authentication.
                        type: str
                    prefix_list_in:
                        description:
                            - IPv4 Inbound filter for updates from this neighbor.
                        type: str
                    prefix_list_in6:
                        description:
                            - IPv6 Inbound filter for updates from this neighbor.
                        type: str
                    prefix_list_out:
                        description:
                            - IPv4 Outbound filter for updates to this neighbor.
                        type: str
                    prefix_list_out6:
                        description:
                            - IPv6 Outbound filter for updates to this neighbor.
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
                            - 'enable'
                            - 'disable'
                    remove_private_as6:
                        description:
                            - Enable/disable remove private AS number from IPv6 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_map_in:
                        description:
                            - IPv4 Inbound route map filter.
                        type: str
                    route_map_in6:
                        description:
                            - IPv6 Inbound route map filter.
                        type: str
                    route_map_in_evpn:
                        description:
                            - EVPN Inbound route map filter.
                        type: str
                    route_map_out:
                        description:
                            - IPv4 outbound route map filter.
                        type: str
                    route_map_out6:
                        description:
                            - IPv6 Outbound route map filter.
                        type: str
                    route_map_out_evpn:
                        description:
                            - EVPN outbound route map filter.
                        type: str
                    route_reflector_client:
                        description:
                            - Enable/disable IPv4 AS route reflector client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client6:
                        description:
                            - Enable/disable IPv6 AS route reflector client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client_evpn:
                        description:
                            - Enable/disable EVPN AS route reflector client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client:
                        description:
                            - Enable/disable IPv4 AS route server client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client6:
                        description:
                            - Enable/disable IPv6 AS route server client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    send_community:
                        description:
                            - IPv4 Send community attribute to neighbor.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    send_community6:
                        description:
                            - IPv6 Send community attribute to neighbor.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    shutdown:
                        description:
                            - Enable/disable shutdown this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration:
                        description:
                            - Enable/disable allow IPv4 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration6:
                        description:
                            - Enable/disable allow IPv6 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration_evpn:
                        description:
                            - Enable/disable allow EVPN inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    strict_capability_match:
                        description:
                            - Enable/disable strict capability matching.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    unsuppress_map:
                        description:
                            - IPv4 Route map to selectively unsuppress suppressed routes.
                        type: str
                    unsuppress_map6:
                        description:
                            - IPv6 Route map to selectively unsuppress suppressed routes.
                        type: str
                    update_source:
                        description:
                            - Interface to use as source IP/IPv6 address of TCP connections.
                        type: str
                    weight:
                        description:
                            - Neighbor weight.
                        type: int
            neighbor_group:
                description:
                    - BGP neighbor group table.
                type: list
                elements: dict
                suboptions:
                    activate:
                        description:
                            - Enable/disable address family IPv4 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate6:
                        description:
                            - Enable/disable address family IPv6 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate_evpn:
                        description:
                            - Enable/disable address family evpn for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    advertisement_interval:
                        description:
                            - Minimum interval (seconds) between sending updates.
                        type: int
                    allowas_in:
                        description:
                            - IPv4 The maximum number of occurrence of my AS number allowed.
                        type: int
                    allowas_in6:
                        description:
                            - IPv6 The maximum number of occurrence of my AS number allowed.
                        type: int
                    allowas_in_enable:
                        description:
                            - Enable/disable IPv4 Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable6:
                        description:
                            - Enable/disable IPv6 - Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable_evpn:
                        description:
                            - Enable/disable EVPN Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    as_override:
                        description:
                            - Enable/disable replace peer AS with own AS for IPv4.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    as_override6:
                        description:
                            - Enable/disable replace peer AS with own AS for IPv6.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    attribute_unchanged:
                        description:
                            - IPv4 List of attributes that should be unchanged.
                        type: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    attribute_unchanged6:
                        description:
                            - IPv6 List of attributes that should be unchanged.
                        type: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    attribute_unchanged_evpn:
                        description:
                            - EVPN List of attributes that should be unchanged.
                        type: str
                        choices:
                            - 'as-path'
                            - 'med'
                    bfd:
                        description:
                            - Enable/disable BFD for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_default_originate:
                        description:
                            - Enable/disable advertise default IPv4 route to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_default_originate6:
                        description:
                            - Enable/disable advertise default IPv6 route to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_dynamic:
                        description:
                            - Enable/disable advertise dynamic capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_extended_nexthop:
                        description:
                            - Enable/disable extended nexthop capability.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_orf:
                        description:
                            - Accept/Send IPv4 ORF lists to/from this neighbor.
                        type: str
                        choices:
                            - 'none'
                            - 'receive'
                            - 'send'
                            - 'both'
                    capability_orf6:
                        description:
                            - Accept/Send IPv6 ORF lists to/from this neighbor.
                        type: str
                        choices:
                            - 'none'
                            - 'receive'
                            - 'send'
                            - 'both'
                    connect_timer:
                        description:
                            - Interval (seconds) for connect timer.
                        type: int
                    default_originate_routemap:
                        description:
                            - Route map to specify criteria to originate IPv4 default.
                        type: str
                    default_originate_routemap6:
                        description:
                            - Route map to specify criteria to originate IPv6 default.
                        type: str
                    description:
                        description:
                            - Description.
                        type: str
                    distribute_list_in:
                        description:
                            - Filter for IPv4 updates from this neighbor.
                        type: str
                    distribute_list_in6:
                        description:
                            - Filter for IPv6 updates from this neighbor.
                        type: str
                    distribute_list_out:
                        description:
                            - Filter for IPv4 updates to this neighbor.
                        type: str
                    distribute_list_out6:
                        description:
                            - Filter for IPv6 updates to this neighbor.
                        type: str
                    dont_capability_negotiate:
                        description:
                            - Don"t negotiate capabilities with this neighbor
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ebgp_enforce_multihop:
                        description:
                            - Enable/disable allow multi-hop next-hops from EBGP neighbors.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ebgp_multihop_ttl:
                        description:
                            - EBGP multihop TTL for this peer.
                        type: int
                    ebgp_ttl_security_hops:
                        description:
                            - Specify the maximum number of hops to the EBGP peer.
                        type: int
                    enforce_first_as:
                        description:
                            - Enable/disable  - Enable to enforce first AS for all(IPV4/IPV6) EBGP routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    filter_list_in:
                        description:
                            - BGP aspath filter for IPv4 inbound routes.
                        type: str
                    filter_list_in6:
                        description:
                            - BGP filter for IPv6 inbound routes.
                        type: str
                    filter_list_out:
                        description:
                            - BGP aspath filter for IPv4 outbound routes.
                        type: str
                    filter_list_out6:
                        description:
                            - BGP filter for IPv6 outbound routes.
                        type: str
                    holdtime_timer:
                        description:
                            - Interval (seconds) before peer considered dead.
                        type: int
                    interface:
                        description:
                            - Interface(s).
                        type: list
                        elements: dict
                        suboptions:
                            interface_name:
                                description:
                                    - RVI interface name(s).
                                type: str
                    keep_alive_timer:
                        description:
                            - Keepalive timer interval (seconds).
                        type: int
                    maximum_prefix:
                        description:
                            - Maximum number of IPv4 prefixes to accept from this peer.
                        type: int
                    maximum_prefix6:
                        description:
                            - Maximum number of IPv6 prefixes to accept from this peer.
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
                            - 'enable'
                            - 'disable'
                    maximum_prefix_warning_only6:
                        description:
                            - Enable/disable IPv6 Only give warning message when threshold is exceeded.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    name:
                        description:
                            - Neighbor group name.
                        type: str
                    next_hop_self:
                        description:
                            - Enable/disable IPv4 next-hop calculation for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self6:
                        description:
                            - Enable/disable IPv6 next-hop calculation for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_capability:
                        description:
                            - Enable/disable override result of capability negotiation.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    passive:
                        description:
                            - Enable/disable sending of open messages to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    password:
                        description:
                            - Password used in MD5 authentication.
                        type: str
                    prefix_list_in:
                        description:
                            - IPv4 Inbound filter for updates from this neighbor.
                        type: str
                    prefix_list_in6:
                        description:
                            - IPv6 Inbound filter for updates from this neighbor.
                        type: str
                    prefix_list_out:
                        description:
                            - IPv4 Outbound filter for updates to this neighbor.
                        type: str
                    prefix_list_out6:
                        description:
                            - IPv6 Outbound filter for updates to this neighbor.
                        type: str
                    remote_as:
                        description:
                            - AS number of neighbor.
                        type: str
                    remove_private_as:
                        description:
                            - Enable/disable remove private AS number from IPv4 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    remove_private_as6:
                        description:
                            - Enable/disable remove private AS number from IPv6 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_map_in:
                        description:
                            - IPv4 Inbound route map filter.
                        type: str
                    route_map_in6:
                        description:
                            - IPv6 Inbound route map filter.
                        type: str
                    route_map_in_evpn:
                        description:
                            - EVPN Inbound route map filter.
                        type: str
                    route_map_out:
                        description:
                            - IPv4 outbound route map filter.
                        type: str
                    route_map_out6:
                        description:
                            - IPv6 Outbound route map filter.
                        type: str
                    route_map_out_evpn:
                        description:
                            - EVPN outbound route map filter.
                        type: str
                    route_reflector_client:
                        description:
                            - Enable/disable IPv4 AS route reflector client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client6:
                        description:
                            - Enable/disable IPv6 AS route reflector client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client_evpn:
                        description:
                            - Enable/disable EVPN AS route reflector client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client:
                        description:
                            - Enable/disable IPv4 AS route server client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client6:
                        description:
                            - Enable/disable IPv6 AS route server client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    send_community:
                        description:
                            - IPv4 Send community attribute to neighbor.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    send_community6:
                        description:
                            - IPv6 Send community attribute to neighbor.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    shutdown:
                        description:
                            - Enable/disable shutdown this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration:
                        description:
                            - Enable/disable allow IPv4 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration6:
                        description:
                            - Enable/disable allow IPv6 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration_evpn:
                        description:
                            - Enable/disable allow EVPN inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    strict_capability_match:
                        description:
                            - Enable/disable strict capability matching.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    unsuppress_map:
                        description:
                            - IPv4 Route map to selectively unsuppress suppressed routes.
                        type: str
                    unsuppress_map6:
                        description:
                            - IPv6 Route map to selectively unsuppress suppressed routes.
                        type: str
                    update_source:
                        description:
                            - Interface to use as source IP/IPv6 address of TCP connections.
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
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - ID.
                        type: int
                    prefix:
                        description:
                            - Network prefix.
                        type: str
                    route_map:
                        description:
                            - Route map to modify generated route.
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
                        type: int
                    prefix6:
                        description:
                            - Network IPv6 prefix.
                        type: str
                    route_map:
                        description:
                            - Route map to modify generated route.
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
                        type: str
                    route_map:
                        description:
                            - Route map name.
                        type: str
                    status:
                        description:
                            - Status
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            redistribute6:
                description:
                    - BGP IPv6 redistribute table.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Distribute list entry name.
                        type: str
                    route_map:
                        description:
                            - Route map name.
                        type: str
                    status:
                        description:
                            - Status
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            route_reflector_allow_outbound_policy:
                description:
                    - Enable/disable route reflector to apply a route-map to reflected routes.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
- name: BGP configuration.
  fortinet.fortiswitch.fortiswitch_router_bgp:
      router_bgp:
          admin_distance:
              -
                  distance: "4"
                  id: "5"
                  neighbour_prefix: "<your_own_value>"
                  route_list: "<your_own_value> (source router.access-list.name)"
          admin_distance6:
              -
                  distance: "9"
                  id: "10"
                  neighbour_prefix6: "<your_own_value>"
                  route6_list: "<your_own_value> (source router.access-list6.name)"
          aggregate_address:
              -
                  as_set: "enable"
                  id: "15"
                  prefix: "<your_own_value>"
                  summary_only: "enable"
          aggregate_address6:
              -
                  id: "19"
                  prefix6: "<your_own_value>"
                  summary_only: "enable"
          always_compare_med: "enable"
          as: "23"
          bestpath_as_path_ignore: "enable"
          bestpath_aspath_multipath_relax: "disable"
          bestpath_cmp_confed_aspath: "enable"
          bestpath_cmp_routerid: "enable"
          bestpath_med_confed: "enable"
          bestpath_med_missing_as_worst: "enable"
          client_to_client_reflection: "enable"
          cluster_id: "<your_own_value>"
          confederation_identifier: "32"
          confederation_peers:
              -
                  peer: "<your_own_value>"
          dampening: "enable"
          dampening_max_suppress_time: "36"
          dampening_reachability_half_life: "37"
          dampening_reuse: "38"
          dampening_suppress: "39"
          default_local_preference: "40"
          deterministic_med: "enable"
          distance_external: "42"
          distance_internal: "43"
          distance_local: "44"
          ebgp_requires_policy: "enable"
          enforce_first_as: "enable"
          fast_external_failover: "enable"
          graceful_stalepath_time: "48"
          holdtime_timer: "49"
          keepalive_timer: "50"
          log_neighbour_changes: "enable"
          maximum_paths_ebgp: "52"
          maximum_paths_ibgp: "53"
          neighbor:
              -
                  activate: "enable"
                  activate6: "enable"
                  activate_evpn: "enable"
                  advertisement_interval: "58"
                  allowas_in: "59"
                  allowas_in6: "60"
                  allowas_in_enable: "enable"
                  allowas_in_enable6: "enable"
                  allowas_in_enable_evpn: "enable"
                  as_override: "enable"
                  as_override6: "enable"
                  attribute_unchanged: "as-path"
                  attribute_unchanged6: "as-path"
                  attribute_unchanged_evpn: "as-path"
                  bfd: "enable"
                  bfd_session_mode: "automatic"
                  capability_default_originate: "enable"
                  capability_default_originate6: "enable"
                  capability_dynamic: "enable"
                  capability_extended_nexthop: "enable"
                  capability_orf: "none"
                  capability_orf6: "none"
                  connect_timer: "77"
                  default_originate_routemap: "<your_own_value> (source router.route-map.name)"
                  default_originate_routemap6: "<your_own_value> (source router.route-map.name)"
                  description: "<your_own_value>"
                  distribute_list_in: "<your_own_value> (source router.access-list.name)"
                  distribute_list_in6: "<your_own_value> (source router.access-list6.name)"
                  distribute_list_out: "<your_own_value> (source router.access-list.name)"
                  distribute_list_out6: "<your_own_value> (source router.access-list6.name)"
                  dont_capability_negotiate: "enable"
                  ebgp_enforce_multihop: "enable"
                  ebgp_multihop_ttl: "87"
                  ebgp_ttl_security_hops: "88"
                  enforce_first_as: "enable"
                  filter_list_in: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_in6: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out6: "<your_own_value> (source router.aspath-list.name)"
                  holdtime_timer: "94"
                  interface: "<your_own_value> (source system.interface.name)"
                  ip: "<your_own_value>"
                  keep_alive_timer: "97"
                  maximum_prefix: "98"
                  maximum_prefix6: "99"
                  maximum_prefix_threshold: "100"
                  maximum_prefix_threshold6: "101"
                  maximum_prefix_warning_only: "enable"
                  maximum_prefix_warning_only6: "enable"
                  next_hop_self: "enable"
                  next_hop_self6: "enable"
                  override_capability: "enable"
                  passive: "enable"
                  password: "<your_own_value>"
                  prefix_list_in: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_in6: "<your_own_value> (source router.prefix-list6.name)"
                  prefix_list_out: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_out6: "<your_own_value> (source router.prefix-list6.name)"
                  remote_as: "113"
                  remove_private_as: "enable"
                  remove_private_as6: "enable"
                  route_map_in: "<your_own_value> (source router.route-map.name)"
                  route_map_in6: "<your_own_value> (source router.route-map.name)"
                  route_map_in_evpn: "<your_own_value> (source router.route-map.name)"
                  route_map_out: "<your_own_value> (source router.route-map.name)"
                  route_map_out6: "<your_own_value> (source router.route-map.name)"
                  route_map_out_evpn: "<your_own_value> (source router.route-map.name)"
                  route_reflector_client: "enable"
                  route_reflector_client6: "enable"
                  route_reflector_client_evpn: "enable"
                  route_server_client: "enable"
                  route_server_client6: "enable"
                  send_community: "standard"
                  send_community6: "standard"
                  shutdown: "enable"
                  soft_reconfiguration: "enable"
                  soft_reconfiguration6: "enable"
                  soft_reconfiguration_evpn: "enable"
                  strict_capability_match: "enable"
                  unsuppress_map: "<your_own_value> (source router.route-map.name)"
                  unsuppress_map6: "<your_own_value> (source router.route-map.name)"
                  update_source: "<your_own_value> (source system.interface.name)"
                  weight: "137"
          neighbor_group:
              -
                  activate: "enable"
                  activate6: "enable"
                  activate_evpn: "enable"
                  advertisement_interval: "142"
                  allowas_in: "143"
                  allowas_in6: "144"
                  allowas_in_enable: "enable"
                  allowas_in_enable6: "enable"
                  allowas_in_enable_evpn: "enable"
                  as_override: "enable"
                  as_override6: "enable"
                  attribute_unchanged: "as-path"
                  attribute_unchanged6: "as-path"
                  attribute_unchanged_evpn: "as-path"
                  bfd: "enable"
                  capability_default_originate: "enable"
                  capability_default_originate6: "enable"
                  capability_dynamic: "enable"
                  capability_extended_nexthop: "enable"
                  capability_orf: "none"
                  capability_orf6: "none"
                  connect_timer: "160"
                  default_originate_routemap: "<your_own_value> (source router.route-map.name)"
                  default_originate_routemap6: "<your_own_value> (source router.route-map.name)"
                  description: "<your_own_value>"
                  distribute_list_in: "<your_own_value> (source router.access-list.name)"
                  distribute_list_in6: "<your_own_value> (source router.access-list6.name)"
                  distribute_list_out: "<your_own_value> (source router.access-list.name)"
                  distribute_list_out6: "<your_own_value> (source router.access-list6.name)"
                  dont_capability_negotiate: "enable"
                  ebgp_enforce_multihop: "enable"
                  ebgp_multihop_ttl: "170"
                  ebgp_ttl_security_hops: "171"
                  enforce_first_as: "enable"
                  filter_list_in: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_in6: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out6: "<your_own_value> (source router.aspath-list.name)"
                  holdtime_timer: "177"
                  interface:
                      -
                          interface_name: "<your_own_value> (source system.interface.name)"
                  keep_alive_timer: "180"
                  maximum_prefix: "181"
                  maximum_prefix6: "182"
                  maximum_prefix_threshold: "183"
                  maximum_prefix_threshold6: "184"
                  maximum_prefix_warning_only: "enable"
                  maximum_prefix_warning_only6: "enable"
                  name: "default_name_187"
                  next_hop_self: "enable"
                  next_hop_self6: "enable"
                  override_capability: "enable"
                  passive: "enable"
                  password: "<your_own_value>"
                  prefix_list_in: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_in6: "<your_own_value> (source router.prefix-list6.name)"
                  prefix_list_out: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_out6: "<your_own_value> (source router.prefix-list6.name)"
                  remote_as: "<your_own_value>"
                  remove_private_as: "enable"
                  remove_private_as6: "enable"
                  route_map_in: "<your_own_value> (source router.route-map.name)"
                  route_map_in6: "<your_own_value> (source router.route-map.name)"
                  route_map_in_evpn: "<your_own_value> (source router.route-map.name)"
                  route_map_out: "<your_own_value> (source router.route-map.name)"
                  route_map_out6: "<your_own_value> (source router.route-map.name)"
                  route_map_out_evpn: "<your_own_value> (source router.route-map.name)"
                  route_reflector_client: "enable"
                  route_reflector_client6: "enable"
                  route_reflector_client_evpn: "enable"
                  route_server_client: "enable"
                  route_server_client6: "enable"
                  send_community: "standard"
                  send_community6: "standard"
                  shutdown: "enable"
                  soft_reconfiguration: "enable"
                  soft_reconfiguration6: "enable"
                  soft_reconfiguration_evpn: "enable"
                  strict_capability_match: "enable"
                  unsuppress_map: "<your_own_value> (source router.route-map.name)"
                  unsuppress_map6: "<your_own_value> (source router.route-map.name)"
                  update_source: "<your_own_value> (source system.interface.name)"
                  weight: "221"
          network:
              -
                  backdoor: "enable"
                  id: "224"
                  prefix: "<your_own_value>"
                  route_map: "<your_own_value> (source router.route-map.name)"
          network6:
              -
                  id: "228"
                  prefix6: "<your_own_value>"
                  route_map: "<your_own_value> (source router.route-map.name)"
          redistribute:
              -
                  name: "default_name_232"
                  route_map: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          redistribute6:
              -
                  name: "default_name_236"
                  route_map: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          route_reflector_allow_outbound_policy: "enable"
          router_id: "<your_own_value>"
          scan_time: "241"
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


def filter_router_bgp_data(json):
    option_list = ['admin_distance', 'admin_distance6', 'aggregate_address',
                   'aggregate_address6', 'always_compare_med', 'as',
                   'bestpath_as_path_ignore', 'bestpath_aspath_multipath_relax', 'bestpath_cmp_confed_aspath',
                   'bestpath_cmp_routerid', 'bestpath_med_confed', 'bestpath_med_missing_as_worst',
                   'client_to_client_reflection', 'cluster_id', 'confederation_identifier',
                   'confederation_peers', 'dampening', 'dampening_max_suppress_time',
                   'dampening_reachability_half_life', 'dampening_reuse', 'dampening_suppress',
                   'default_local_preference', 'deterministic_med', 'distance_external',
                   'distance_internal', 'distance_local', 'ebgp_requires_policy',
                   'enforce_first_as', 'fast_external_failover', 'graceful_stalepath_time',
                   'holdtime_timer', 'keepalive_timer', 'log_neighbour_changes',
                   'maximum_paths_ebgp', 'maximum_paths_ibgp', 'neighbor',
                   'neighbor_group', 'network', 'network6',
                   'redistribute', 'redistribute6', 'route_reflector_allow_outbound_policy',
                   'router_id', 'scan_time']

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


def router_bgp(data, fos, check_mode=False):
    state = data.get('state', None)

    router_bgp_data = data['router_bgp']

    filtered_data = filter_router_bgp_data(router_bgp_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('router', 'bgp', filtered_data)
        current_data = fos.get('router', 'bgp', mkey=mkey)
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

    return fos.set('router',
                   'bgp',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_router(data, fos, check_mode):
    fos.do_member_operation('router', 'bgp')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['router_bgp']:
        resp = router_bgp(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('router_bgp'))
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
        "confederation_peers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "peer": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "peer",
                    "help": "Peer ID.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "confederation-peers",
            "help": "Confederation peers.",
            "mkey": "peer",
            "category": "table"
        },
        "distance_internal": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "distance-internal",
            "help": "Distance for routes internal to the AS.",
            "category": "unitary"
        },
        "aggregate_address6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "summary_only": {
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
                    "name": "summary-only",
                    "help": "Enable/disable filter more specific routes from updates.",
                    "category": "unitary"
                },
                "id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "id",
                    "help": "ID.",
                    "category": "unitary"
                },
                "prefix6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "prefix6",
                    "help": "Aggregate IPv6 prefix.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "aggregate-address6",
            "help": "BGP IPv6 aggregate address table.",
            "mkey": "id",
            "category": "table"
        },
        "dampening_suppress": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "dampening-suppress",
            "help": "Threshold to suppress routes.",
            "category": "unitary"
        },
        "bestpath_cmp_confed_aspath": {
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
            "name": "bestpath-cmp-confed-aspath",
            "help": "Enable/disable compare federation AS path length.",
            "category": "unitary"
        },
        "keepalive_timer": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "keepalive-timer",
            "help": "Frequency to send keepalive requests.",
            "category": "unitary"
        },
        "as": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "as",
            "help": "Router AS number.",
            "category": "unitary"
        },
        "dampening_reachability_half_life": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "dampening-reachability-half-life",
            "help": "Reachability half-life time for penalty (minutes).",
            "category": "unitary"
        },
        "admin_distance": {
            "type": "list",
            "elements": "dict",
            "children": {
                "distance": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "distance",
                    "help": "Administrative distance to apply (1 - 255).",
                    "category": "unitary"
                },
                "neighbour_prefix": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "neighbour-prefix",
                    "help": "Neighbor address prefix.",
                    "category": "unitary"
                },
                "route_list": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-list",
                    "help": "Access list of routes to apply new distance to.",
                    "category": "unitary"
                },
                "id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "id",
                    "help": "ID.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "admin-distance",
            "help": "Administrative distance modifications.",
            "mkey": "id",
            "category": "table"
        },
        "distance_external": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "distance-external",
            "help": "Distance for routes external to the AS.",
            "category": "unitary"
        },
        "dampening": {
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
            "name": "dampening",
            "help": "Enable/disable route-flap dampening.",
            "category": "unitary"
        },
        "network": {
            "type": "list",
            "elements": "dict",
            "children": {
                "backdoor": {
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
                    "name": "backdoor",
                    "help": "Enable/disable route as backdoor.",
                    "category": "unitary"
                },
                "prefix": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "prefix",
                    "help": "Network prefix.",
                    "category": "unitary"
                },
                "route_map": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-map",
                    "help": "Route map to modify generated route.",
                    "category": "unitary"
                },
                "id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "id",
                    "help": "ID.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "network",
            "help": "BGP network table.",
            "mkey": "id",
            "category": "table"
        },
        "router_id": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "router-id",
            "help": "Router ID.",
            "category": "unitary"
        },
        "aggregate_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "as_set": {
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
                    "name": "as-set",
                    "help": "Enable/disable generate AS set path information.",
                    "category": "unitary"
                },
                "prefix": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "prefix",
                    "help": "Aggregate prefix.",
                    "category": "unitary"
                },
                "id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "id",
                    "help": "ID.",
                    "category": "unitary"
                },
                "summary_only": {
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
                    "name": "summary-only",
                    "help": "Enable/disable filter more specific routes from updates.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "aggregate-address",
            "help": "BGP aggregate address table.",
            "mkey": "id",
            "category": "table"
        },
        "distance_local": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "distance-local",
            "help": "Distance for routes local to the AS.",
            "category": "unitary"
        },
        "bestpath_med_confed": {
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
            "name": "bestpath-med-confed",
            "help": "Enable/disable compare MED among confederation paths.",
            "category": "unitary"
        },
        "default_local_preference": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "default-local-preference",
            "help": "Default local preference.",
            "category": "unitary"
        },
        "bestpath_cmp_routerid": {
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
            "name": "bestpath-cmp-routerid",
            "help": "Enable/disable compare router ID for identical EBGP paths.",
            "category": "unitary"
        },
        "bestpath_aspath_multipath_relax": {
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
            "name": "bestpath-aspath-multipath-relax",
            "help": "Allow load sharing across routes that have different AS paths (but same length).",
            "category": "unitary"
        },
        "graceful_stalepath_time": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "graceful-stalepath-time",
            "help": "Time to hold stale paths of restarting neighbour(sec).",
            "category": "unitary"
        },
        "enforce_first_as": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
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
            "name": "enforce-first-as",
            "help": "Enable/disable enforce first AS for EBGP routes.",
            "category": "unitary"
        },
        "cluster_id": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "cluster-id",
            "help": "Route reflector cluster ID.",
            "category": "unitary"
        },
        "scan_time": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "scan-time",
            "help": "Background scanner interval (seconds).",
            "category": "unitary"
        },
        "bestpath_med_missing_as_worst": {
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
            "name": "bestpath-med-missing-as-worst",
            "help": "Enable/disable treat missing MED as least preferred.",
            "category": "unitary"
        },
        "holdtime_timer": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "holdtime-timer",
            "help": "Number of seconds to mark peer as dead.",
            "category": "unitary"
        },
        "network6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "route_map": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-map",
                    "help": "Route map to modify generated route.",
                    "category": "unitary"
                },
                "id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "id",
                    "help": "ID.",
                    "category": "unitary"
                },
                "prefix6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "prefix6",
                    "help": "Network IPv6 prefix.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "network6",
            "help": "BGP IPv6 network table.",
            "mkey": "id",
            "category": "table"
        },
        "dampening_reuse": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "dampening-reuse",
            "help": "Threshold to unsuppress routes.",
            "category": "unitary"
        },
        "always_compare_med": {
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
            "name": "always-compare-med",
            "help": "Enable/disable always compare MED.",
            "category": "unitary"
        },
        "maximum_paths_ebgp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "maximum-paths-ebgp",
            "help": "Maximum paths for ebgp ecmp.",
            "category": "unitary"
        },
        "bestpath_as_path_ignore": {
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
            "name": "bestpath-as-path-ignore",
            "help": "Enable/disable ignore AS path.",
            "category": "unitary"
        },
        "redistribute": {
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
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "status",
                    "help": "Status",
                    "category": "unitary"
                },
                "route_map": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-map",
                    "help": "Route map name.",
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
                    "help": "Redistribute protocol name.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "redistribute",
            "help": "BGP IPv4 redistribute table.",
            "mkey": "name",
            "category": "table"
        },
        "client_to_client_reflection": {
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
            "name": "client-to-client-reflection",
            "help": "Enable/disable client-to-client route reflection.",
            "category": "unitary"
        },
        "dampening_max_suppress_time": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "dampening-max-suppress-time",
            "help": "Maximum minutes a route can be suppressed.",
            "category": "unitary"
        },
        "deterministic_med": {
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
            "name": "deterministic-med",
            "help": "Enable/disable enforce deterministic comparison of MED.",
            "category": "unitary"
        },
        "fast_external_failover": {
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
            "name": "fast-external-failover",
            "help": "Enable/disable reset peer BGP session if link goes down.",
            "category": "unitary"
        },
        "maximum_paths_ibgp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "maximum-paths-ibgp",
            "help": "Maximum paths for ibgp ecmp.",
            "category": "unitary"
        },
        "redistribute6": {
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
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "status",
                    "help": "Status",
                    "category": "unitary"
                },
                "route_map": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-map",
                    "help": "Route map name.",
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
                    "help": "Distribute list entry name.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "redistribute6",
            "help": "BGP IPv6 redistribute table.",
            "mkey": "name",
            "category": "table"
        },
        "log_neighbour_changes": {
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
            "name": "log-neighbour-changes",
            "help": "Enable logging of BGP neighbour's changes",
            "category": "unitary"
        },
        "neighbor": {
            "type": "list",
            "elements": "dict",
            "children": {
                "send_community": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "standard"
                        },
                        {
                            "value": "extended"
                        },
                        {
                            "value": "both"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "send-community",
                    "help": "IPv4 Send community attribute to neighbor.",
                    "category": "unitary"
                },
                "activate": {
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
                    "name": "activate",
                    "help": "Enable/disable address family IPv4 for this neighbor.",
                    "category": "unitary"
                },
                "filter_list_out6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "filter-list-out6",
                    "help": "BGP filter for IPv6 outbound routes.",
                    "category": "unitary"
                },
                "weight": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "weight",
                    "help": "Neighbor weight.",
                    "category": "unitary"
                },
                "attribute_unchanged": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "as-path"
                        },
                        {
                            "value": "med"
                        },
                        {
                            "value": "next-hop"
                        }
                    ],
                    "name": "attribute-unchanged",
                    "help": "IPv4 List of attributes that should be unchanged.",
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
                    "help": "IP/IPv6 address of neighbor.",
                    "category": "unitary"
                },
                "filter_list_in6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "filter-list-in6",
                    "help": "BGP filter for IPv6 inbound routes.",
                    "category": "unitary"
                },
                "ebgp_multihop_ttl": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ebgp-multihop-ttl",
                    "help": "EBGP multihop TTL for this peer.",
                    "category": "unitary"
                },
                "default_originate_routemap": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "default-originate-routemap",
                    "help": "Route map to specify criteria to originate IPv4 default.",
                    "category": "unitary"
                },
                "default_originate_routemap6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "default-originate-routemap6",
                    "help": "Route map to specify criteria to originate IPv6 default.",
                    "category": "unitary"
                },
                "route_reflector_client": {
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
                    "name": "route-reflector-client",
                    "help": "Enable/disable IPv4 AS route reflector client.",
                    "category": "unitary"
                },
                "route_map_out6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-map-out6",
                    "help": "IPv6 Outbound route map filter.",
                    "category": "unitary"
                },
                "remove_private_as": {
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
                    "name": "remove-private-as",
                    "help": "Enable/disable remove private AS number from IPv4 outbound updates.",
                    "category": "unitary"
                },
                "shutdown": {
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
                    "name": "shutdown",
                    "help": "Enable/disable shutdown this neighbor.",
                    "category": "unitary"
                },
                "route_map_in6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-map-in6",
                    "help": "IPv6 Inbound route map filter.",
                    "category": "unitary"
                },
                "unsuppress_map6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "unsuppress-map6",
                    "help": "IPv6 Route map to selectively unsuppress suppressed routes.",
                    "category": "unitary"
                },
                "unsuppress_map": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "unsuppress-map",
                    "help": "IPv4 Route map to selectively unsuppress suppressed routes.",
                    "category": "unitary"
                },
                "as_override6": {
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
                    "name": "as-override6",
                    "help": "Enable/disable replace peer AS with own AS for IPv6.",
                    "category": "unitary"
                },
                "attribute_unchanged6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "as-path"
                        },
                        {
                            "value": "med"
                        },
                        {
                            "value": "next-hop"
                        }
                    ],
                    "name": "attribute-unchanged6",
                    "help": "IPv6 List of attributes that should be unchanged.",
                    "category": "unitary"
                },
                "ebgp_enforce_multihop": {
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
                    "name": "ebgp-enforce-multihop",
                    "help": "Enable/disable allow multi-hop next-hops from EBGP neighbors.",
                    "category": "unitary"
                },
                "advertisement_interval": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "advertisement-interval",
                    "help": "Minimum interval (seconds) between sending updates.",
                    "category": "unitary"
                },
                "prefix_list_in6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "prefix-list-in6",
                    "help": "IPv6 Inbound filter for updates from this neighbor.",
                    "category": "unitary"
                },
                "capability_default_originate6": {
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
                    "name": "capability-default-originate6",
                    "help": "Enable/disable advertise default IPv6 route to this neighbor.",
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
                    "help": "Enable/disable BFD for this neighbor.",
                    "category": "unitary"
                },
                "capability_orf": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "none"
                        },
                        {
                            "value": "receive"
                        },
                        {
                            "value": "send"
                        },
                        {
                            "value": "both"
                        }
                    ],
                    "name": "capability-orf",
                    "help": "Accept/Send IPv4 ORF lists to/from this neighbor.",
                    "category": "unitary"
                },
                "next_hop_self": {
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
                    "name": "next-hop-self",
                    "help": "Enable/disable IPv4 next-hop calculation for this neighbor.",
                    "category": "unitary"
                },
                "allowas_in_enable": {
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
                    "name": "allowas-in-enable",
                    "help": "Enable/disable IPv4 Enable to allow my AS in AS path.",
                    "category": "unitary"
                },
                "route_reflector_client6": {
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
                    "name": "route-reflector-client6",
                    "help": "Enable/disable IPv6 AS route reflector client.",
                    "category": "unitary"
                },
                "dont_capability_negotiate": {
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
                    "name": "dont-capability-negotiate",
                    "help": "Don't negotiate capabilities with this neighbor",
                    "category": "unitary"
                },
                "connect_timer": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "connect-timer",
                    "help": "Interval (seconds) for connect timer.",
                    "category": "unitary"
                },
                "passive": {
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
                    "name": "passive",
                    "help": "Enable/disable sending of open messages to this neighbor.",
                    "category": "unitary"
                },
                "allowas_in": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "allowas-in",
                    "help": "IPv4 The maximum number of occurrence of my AS number allowed.",
                    "category": "unitary"
                },
                "maximum_prefix6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "maximum-prefix6",
                    "help": "Maximum number of IPv6 prefixes to accept from this peer.",
                    "category": "unitary"
                },
                "route_server_client": {
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
                    "name": "route-server-client",
                    "help": "Enable/disable IPv4 AS route server client.",
                    "category": "unitary"
                },
                "maximum_prefix_threshold": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "maximum-prefix-threshold",
                    "help": "Maximum IPv4 prefix threshold value (1-100 percent).",
                    "category": "unitary"
                },
                "filter_list_out": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "filter-list-out",
                    "help": "BGP aspath filter for IPv4 outbound routes.",
                    "category": "unitary"
                },
                "keep_alive_timer": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "keep-alive-timer",
                    "help": "Keepalive timer interval (seconds).",
                    "category": "unitary"
                },
                "maximum_prefix_warning_only": {
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
                    "name": "maximum-prefix-warning-only",
                    "help": "Enable/disable IPv4 Only give warning message when threshold is exceeded.",
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
                "as_override": {
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
                    "name": "as-override",
                    "help": "Enable/disable replace peer AS with own AS for IPv4.",
                    "category": "unitary"
                },
                "bfd_session_mode": {
                    "v_range": [
                        [
                            "v7.0.0",
                            "v7.2.1"
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "automatic"
                        },
                        {
                            "value": "multihop"
                        },
                        {
                            "value": "singlehop"
                        }
                    ],
                    "name": "bfd-session-mode",
                    "help": "Single or multihop BFD session to this neighbor.",
                    "category": "unitary"
                },
                "distribute_list_out": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "distribute-list-out",
                    "help": "Filter for IPv4 updates to this neighbor.",
                    "category": "unitary"
                },
                "capability_orf6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "none"
                        },
                        {
                            "value": "receive"
                        },
                        {
                            "value": "send"
                        },
                        {
                            "value": "both"
                        }
                    ],
                    "name": "capability-orf6",
                    "help": "Accept/Send IPv6 ORF lists to/from this neighbor.",
                    "category": "unitary"
                },
                "soft_reconfiguration6": {
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
                    "name": "soft-reconfiguration6",
                    "help": "Enable/disable allow IPv6 inbound soft reconfiguration.",
                    "category": "unitary"
                },
                "maximum_prefix_warning_only6": {
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
                    "name": "maximum-prefix-warning-only6",
                    "help": "Enable/disable IPv6 Only give warning message when threshold is exceeded.",
                    "category": "unitary"
                },
                "next_hop_self6": {
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
                    "name": "next-hop-self6",
                    "help": "Enable/disable IPv6 next-hop calculation for this neighbor.",
                    "category": "unitary"
                },
                "allowas_in_enable6": {
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
                    "name": "allowas-in-enable6",
                    "help": "Enable/disable IPv6 Enable to allow my AS in AS path.",
                    "category": "unitary"
                },
                "allowas_in6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "allowas-in6",
                    "help": "IPv6 The maximum number of occurrence of my AS number allowed.",
                    "category": "unitary"
                },
                "update_source": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "update-source",
                    "help": "Interface to use as source IP/IPv6 address of TCP connections.",
                    "category": "unitary"
                },
                "interface": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "interface",
                    "help": "Interface.",
                    "category": "unitary"
                },
                "remove_private_as6": {
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
                    "name": "remove-private-as6",
                    "help": "Enable/disable remove private AS number from IPv6 outbound updates.",
                    "category": "unitary"
                },
                "password": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "password",
                    "help": "Password used in MD5 authentication.",
                    "category": "unitary"
                },
                "holdtime_timer": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "holdtime-timer",
                    "help": "Interval (seconds) before peer considered dead.",
                    "category": "unitary"
                },
                "route_map_in": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-map-in",
                    "help": "IPv4 Inbound route map filter.",
                    "category": "unitary"
                },
                "activate6": {
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
                    "name": "activate6",
                    "help": "Enable/disable address family IPv6 for this neighbor.",
                    "category": "unitary"
                },
                "filter_list_in": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "filter-list-in",
                    "help": "BGP aspath filter for IPv4 inbound routes.",
                    "category": "unitary"
                },
                "maximum_prefix": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "maximum-prefix",
                    "help": "Maximum number of IPv4 prefixes to accept from this peer.",
                    "category": "unitary"
                },
                "route_server_client6": {
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
                    "name": "route-server-client6",
                    "help": "Enable/disable IPv6 AS route server client.",
                    "category": "unitary"
                },
                "capability_dynamic": {
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
                    "name": "capability-dynamic",
                    "help": "Enable/disable advertise dynamic capability to this neighbor.",
                    "category": "unitary"
                },
                "ebgp_ttl_security_hops": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ebgp-ttl-security-hops",
                    "help": "Specify the maximum number of hops to the EBGP peer.",
                    "category": "unitary"
                },
                "distribute_list_in6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "distribute-list-in6",
                    "help": "Filter for IPv6 updates from this neighbor.",
                    "category": "unitary"
                },
                "override_capability": {
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
                    "name": "override-capability",
                    "help": "Enable/disable override result of capability negotiation.",
                    "category": "unitary"
                },
                "distribute_list_out6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "distribute-list-out6",
                    "help": "Filter for IPv6 updates to this neighbor.",
                    "category": "unitary"
                },
                "send_community6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "standard"
                        },
                        {
                            "value": "extended"
                        },
                        {
                            "value": "both"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "send-community6",
                    "help": "IPv6 Send community attribute to neighbor.",
                    "category": "unitary"
                },
                "route_map_out": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-map-out",
                    "help": "IPv4 outbound route map filter.",
                    "category": "unitary"
                },
                "prefix_list_out6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "prefix-list-out6",
                    "help": "IPv6 Outbound filter for updates to this neighbor.",
                    "category": "unitary"
                },
                "capability_default_originate": {
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
                    "name": "capability-default-originate",
                    "help": "Enable/disable advertise default IPv4 route to this neighbor.",
                    "category": "unitary"
                },
                "strict_capability_match": {
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
                    "name": "strict-capability-match",
                    "help": "Enable/disable strict capability matching.",
                    "category": "unitary"
                },
                "prefix_list_in": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "prefix-list-in",
                    "help": "IPv4 Inbound filter for updates from this neighbor.",
                    "category": "unitary"
                },
                "distribute_list_in": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "distribute-list-in",
                    "help": "Filter for IPv4 updates from this neighbor.",
                    "category": "unitary"
                },
                "remote_as": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "remote-as",
                    "help": "AS number of neighbor.",
                    "category": "unitary"
                },
                "maximum_prefix_threshold6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "maximum-prefix-threshold6",
                    "help": "Maximum IPv6 prefix threshold value (1-100 percent)",
                    "category": "unitary"
                },
                "prefix_list_out": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "prefix-list-out",
                    "help": "IPv4 Outbound filter for updates to this neighbor.",
                    "category": "unitary"
                },
                "soft_reconfiguration": {
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
                    "name": "soft-reconfiguration",
                    "help": "Enable/disable allow IPv4 inbound soft reconfiguration.",
                    "category": "unitary"
                },
                "enforce_first_as": {
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
                    "name": "enforce-first-as",
                    "help": "Enable/disable  - Enable to enforce first AS for all(IPV4/IPV6) EBGP routes.",
                    "category": "unitary"
                },
                "route_map_in_evpn": {
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-map-in-evpn",
                    "help": "EVPN Inbound route map filter.",
                    "category": "unitary"
                },
                "activate_evpn": {
                    "v_range": [
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
                    "name": "activate-evpn",
                    "help": "Enable/disable address family evpn for this neighbor.",
                    "category": "unitary"
                },
                "attribute_unchanged_evpn": {
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "as-path"
                        },
                        {
                            "value": "med"
                        }
                    ],
                    "name": "attribute-unchanged-evpn",
                    "help": "EVPN List of attributes that should be unchanged.",
                    "category": "unitary"
                },
                "soft_reconfiguration_evpn": {
                    "v_range": [
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
                    "name": "soft-reconfiguration-evpn",
                    "help": "Enable/disable allow EVPN inbound soft reconfiguration.",
                    "category": "unitary"
                },
                "route_reflector_client_evpn": {
                    "v_range": [
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
                    "name": "route-reflector-client-evpn",
                    "help": "Enable/disable EVPN AS route reflector client.",
                    "category": "unitary"
                },
                "route_map_out_evpn": {
                    "v_range": [
                        [
                            "v7.4.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route-map-out-evpn",
                    "help": "EVPN outbound route map filter.",
                    "category": "unitary"
                },
                "allowas_in_enable_evpn": {
                    "v_range": [
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
                    "name": "allowas-in-enable-evpn",
                    "help": "Enable/disable EVPN Enable to allow my AS in AS path.",
                    "category": "unitary"
                },
                "capability_extended_nexthop": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "capability-extended-nexthop",
                    "help": "Enable/disable extended nexthop capability.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "neighbor",
            "help": "BGP neighbor table.",
            "mkey": "ip",
            "category": "table"
        },
        "confederation_identifier": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "confederation-identifier",
            "help": "Confederation identifier.",
            "category": "unitary"
        },
        "admin_distance6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "neighbour_prefix6": {
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "neighbour-prefix6",
                    "help": "Neighbor IPV6 prefix.",
                    "category": "unitary"
                },
                "distance": {
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "distance",
                    "help": "Administrative distance to apply (1 - 255).",
                    "category": "unitary"
                },
                "id": {
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "id",
                    "help": "ID.",
                    "category": "unitary"
                },
                "route6_list": {
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "route6-list",
                    "help": "Access list of routes to apply new distance to.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.2.1",
                    ""
                ]
            ],
            "name": "admin-distance6",
            "help": "Administrative distance modifications.",
            "mkey": "id",
            "category": "table"
        },
        "ebgp_requires_policy": {
            "v_range": [
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
            "name": "ebgp-requires-policy",
            "help": "Enable/disable require in and out policy for eBGP peers (RFC8212).",
            "category": "unitary"
        },
        "route_reflector_allow_outbound_policy": {
            "v_range": [
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
            "name": "route-reflector-allow-outbound-policy",
            "help": "Enable/disable route reflector to apply a route-map to reflected routes.",
            "category": "unitary"
        },
        "neighbor_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [],
                    "type": "string",
                    "name": "name",
                    "help": "Neighbor group name.",
                    "category": "unitary"
                },
                "advertisement_interval": {
                    "v_range": [],
                    "type": "integer",
                    "name": "advertisement-interval",
                    "help": "Minimum interval (seconds) between sending updates.",
                    "category": "unitary"
                },
                "allowas_in_enable": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "allowas-in-enable",
                    "help": "Enable/disable IPv4 Enable to allow my AS in AS path.",
                    "category": "unitary"
                },
                "allowas_in_enable_evpn": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "allowas-in-enable-evpn",
                    "help": "Enable/disable EVPN Enable to allow my AS in AS path.",
                    "category": "unitary"
                },
                "allowas_in_enable6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "allowas-in-enable6",
                    "help": "Enable/disable IPv6 - Enable to allow my AS in AS path.",
                    "category": "unitary"
                },
                "enforce_first_as": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "enforce-first-as",
                    "help": "Enable/disable  - Enable to enforce first AS for all(IPV4/IPV6) EBGP routes.",
                    "category": "unitary"
                },
                "allowas_in": {
                    "v_range": [],
                    "type": "integer",
                    "name": "allowas-in",
                    "help": "IPv4 The maximum number of occurrence of my AS number allowed.",
                    "category": "unitary"
                },
                "allowas_in6": {
                    "v_range": [],
                    "type": "integer",
                    "name": "allowas-in6",
                    "help": "IPv6 The maximum number of occurrence of my AS number allowed.",
                    "category": "unitary"
                },
                "attribute_unchanged": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "as-path"
                        },
                        {
                            "value": "med"
                        },
                        {
                            "value": "next-hop"
                        }
                    ],
                    "name": "attribute-unchanged",
                    "help": "IPv4 List of attributes that should be unchanged.",
                    "category": "unitary"
                },
                "attribute_unchanged_evpn": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "as-path"
                        },
                        {
                            "value": "med"
                        }
                    ],
                    "name": "attribute-unchanged-evpn",
                    "help": "EVPN List of attributes that should be unchanged.",
                    "category": "unitary"
                },
                "attribute_unchanged6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "as-path"
                        },
                        {
                            "value": "med"
                        },
                        {
                            "value": "next-hop"
                        }
                    ],
                    "name": "attribute-unchanged6",
                    "help": "IPv6 List of attributes that should be unchanged.",
                    "category": "unitary"
                },
                "activate": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "activate",
                    "help": "Enable/disable address family IPv4 for this neighbor.",
                    "category": "unitary"
                },
                "activate6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "activate6",
                    "help": "Enable/disable address family IPv6 for this neighbor.",
                    "category": "unitary"
                },
                "activate_evpn": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "activate-evpn",
                    "help": "Enable/disable address family evpn for this neighbor.",
                    "category": "unitary"
                },
                "bfd": {
                    "v_range": [],
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
                    "help": "Enable/disable BFD for this neighbor.",
                    "category": "unitary"
                },
                "capability_dynamic": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "capability-dynamic",
                    "help": "Enable/disable advertise dynamic capability to this neighbor.",
                    "category": "unitary"
                },
                "capability_orf": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "none"
                        },
                        {
                            "value": "receive"
                        },
                        {
                            "value": "send"
                        },
                        {
                            "value": "both"
                        }
                    ],
                    "name": "capability-orf",
                    "help": "Accept/Send IPv4 ORF lists to/from this neighbor.",
                    "category": "unitary"
                },
                "capability_orf6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "none"
                        },
                        {
                            "value": "receive"
                        },
                        {
                            "value": "send"
                        },
                        {
                            "value": "both"
                        }
                    ],
                    "name": "capability-orf6",
                    "help": "Accept/Send IPv6 ORF lists to/from this neighbor.",
                    "category": "unitary"
                },
                "capability_default_originate": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "capability-default-originate",
                    "help": "Enable/disable advertise default IPv4 route to this neighbor.",
                    "category": "unitary"
                },
                "capability_default_originate6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "capability-default-originate6",
                    "help": "Enable/disable advertise default IPv6 route to this neighbor.",
                    "category": "unitary"
                },
                "capability_extended_nexthop": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "capability-extended-nexthop",
                    "help": "Enable/disable extended nexthop capability.",
                    "category": "unitary"
                },
                "dont_capability_negotiate": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "dont-capability-negotiate",
                    "help": "Don't negotiate capabilities with this neighbor",
                    "category": "unitary"
                },
                "ebgp_enforce_multihop": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "ebgp-enforce-multihop",
                    "help": "Enable/disable allow multi-hop next-hops from EBGP neighbors.",
                    "category": "unitary"
                },
                "next_hop_self": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "next-hop-self",
                    "help": "Enable/disable IPv4 next-hop calculation for this neighbor.",
                    "category": "unitary"
                },
                "next_hop_self6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "next-hop-self6",
                    "help": "Enable/disable IPv6 next-hop calculation for this neighbor.",
                    "category": "unitary"
                },
                "override_capability": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "override-capability",
                    "help": "Enable/disable override result of capability negotiation.",
                    "category": "unitary"
                },
                "passive": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "passive",
                    "help": "Enable/disable sending of open messages to this neighbor.",
                    "category": "unitary"
                },
                "remove_private_as": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "remove-private-as",
                    "help": "Enable/disable remove private AS number from IPv4 outbound updates.",
                    "category": "unitary"
                },
                "remove_private_as6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "remove-private-as6",
                    "help": "Enable/disable remove private AS number from IPv6 outbound updates.",
                    "category": "unitary"
                },
                "route_reflector_client": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "route-reflector-client",
                    "help": "Enable/disable IPv4 AS route reflector client.",
                    "category": "unitary"
                },
                "route_reflector_client_evpn": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "route-reflector-client-evpn",
                    "help": "Enable/disable EVPN AS route reflector client.",
                    "category": "unitary"
                },
                "route_reflector_client6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "route-reflector-client6",
                    "help": "Enable/disable IPv6 AS route reflector client.",
                    "category": "unitary"
                },
                "route_server_client": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "route-server-client",
                    "help": "Enable/disable IPv4 AS route server client.",
                    "category": "unitary"
                },
                "route_server_client6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "route-server-client6",
                    "help": "Enable/disable IPv6 AS route server client.",
                    "category": "unitary"
                },
                "shutdown": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "shutdown",
                    "help": "Enable/disable shutdown this neighbor.",
                    "category": "unitary"
                },
                "soft_reconfiguration": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "soft-reconfiguration",
                    "help": "Enable/disable allow IPv4 inbound soft reconfiguration.",
                    "category": "unitary"
                },
                "soft_reconfiguration_evpn": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "soft-reconfiguration-evpn",
                    "help": "Enable/disable allow EVPN inbound soft reconfiguration.",
                    "category": "unitary"
                },
                "soft_reconfiguration6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "soft-reconfiguration6",
                    "help": "Enable/disable allow IPv6 inbound soft reconfiguration.",
                    "category": "unitary"
                },
                "as_override": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "as-override",
                    "help": "Enable/disable replace peer AS with own AS for IPv4.",
                    "category": "unitary"
                },
                "as_override6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "as-override6",
                    "help": "Enable/disable replace peer AS with own AS for IPv6.",
                    "category": "unitary"
                },
                "strict_capability_match": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "strict-capability-match",
                    "help": "Enable/disable strict capability matching.",
                    "category": "unitary"
                },
                "default_originate_routemap": {
                    "v_range": [],
                    "type": "string",
                    "name": "default-originate-routemap",
                    "help": "Route map to specify criteria to originate IPv4 default.",
                    "category": "unitary"
                },
                "default_originate_routemap6": {
                    "v_range": [],
                    "type": "string",
                    "name": "default-originate-routemap6",
                    "help": "Route map to specify criteria to originate IPv6 default.",
                    "category": "unitary"
                },
                "description": {
                    "v_range": [],
                    "type": "string",
                    "name": "description",
                    "help": "Description.",
                    "category": "unitary"
                },
                "distribute_list_in": {
                    "v_range": [],
                    "type": "string",
                    "name": "distribute-list-in",
                    "help": "Filter for IPv4 updates from this neighbor.",
                    "category": "unitary"
                },
                "distribute_list_in6": {
                    "v_range": [],
                    "type": "string",
                    "name": "distribute-list-in6",
                    "help": "Filter for IPv6 updates from this neighbor.",
                    "category": "unitary"
                },
                "distribute_list_out": {
                    "v_range": [],
                    "type": "string",
                    "name": "distribute-list-out",
                    "help": "Filter for IPv4 updates to this neighbor.",
                    "category": "unitary"
                },
                "distribute_list_out6": {
                    "v_range": [],
                    "type": "string",
                    "name": "distribute-list-out6",
                    "help": "Filter for IPv6 updates to this neighbor.",
                    "category": "unitary"
                },
                "ebgp_multihop_ttl": {
                    "v_range": [],
                    "type": "integer",
                    "name": "ebgp-multihop-ttl",
                    "help": "EBGP multihop TTL for this peer.",
                    "category": "unitary"
                },
                "ebgp_ttl_security_hops": {
                    "v_range": [],
                    "type": "integer",
                    "name": "ebgp-ttl-security-hops",
                    "help": "Specify the maximum number of hops to the EBGP peer.",
                    "category": "unitary"
                },
                "filter_list_in": {
                    "v_range": [],
                    "type": "string",
                    "name": "filter-list-in",
                    "help": "BGP aspath filter for IPv4 inbound routes.",
                    "category": "unitary"
                },
                "filter_list_in6": {
                    "v_range": [],
                    "type": "string",
                    "name": "filter-list-in6",
                    "help": "BGP filter for IPv6 inbound routes.",
                    "category": "unitary"
                },
                "filter_list_out": {
                    "v_range": [],
                    "type": "string",
                    "name": "filter-list-out",
                    "help": "BGP aspath filter for IPv4 outbound routes.",
                    "category": "unitary"
                },
                "filter_list_out6": {
                    "v_range": [],
                    "type": "string",
                    "name": "filter-list-out6",
                    "help": "BGP filter for IPv6 outbound routes.",
                    "category": "unitary"
                },
                "interface": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "interface_name": {
                            "v_range": [],
                            "type": "string",
                            "name": "interface-name",
                            "help": "RVI interface name(s).",
                            "category": "unitary"
                        }
                    },
                    "v_range": [],
                    "name": "interface",
                    "help": "Interface(s).",
                    "mkey": "interface-name",
                    "category": "table"
                },
                "maximum_prefix": {
                    "v_range": [],
                    "type": "integer",
                    "name": "maximum-prefix",
                    "help": "Maximum number of IPv4 prefixes to accept from this peer.",
                    "category": "unitary"
                },
                "maximum_prefix6": {
                    "v_range": [],
                    "type": "integer",
                    "name": "maximum-prefix6",
                    "help": "Maximum number of IPv6 prefixes to accept from this peer.",
                    "category": "unitary"
                },
                "maximum_prefix_threshold": {
                    "v_range": [],
                    "type": "integer",
                    "name": "maximum-prefix-threshold",
                    "help": "Maximum IPv4 prefix threshold value (1-100 percent).",
                    "category": "unitary"
                },
                "maximum_prefix_threshold6": {
                    "v_range": [],
                    "type": "integer",
                    "name": "maximum-prefix-threshold6",
                    "help": "Maximum IPv6 prefix threshold value (1-100 percent)",
                    "category": "unitary"
                },
                "maximum_prefix_warning_only": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "maximum-prefix-warning-only",
                    "help": "Enable/disable IPv4 Only give warning message when threshold is exceeded.",
                    "category": "unitary"
                },
                "maximum_prefix_warning_only6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "maximum-prefix-warning-only6",
                    "help": "Enable/disable IPv6 Only give warning message when threshold is exceeded.",
                    "category": "unitary"
                },
                "prefix_list_in": {
                    "v_range": [],
                    "type": "string",
                    "name": "prefix-list-in",
                    "help": "IPv4 Inbound filter for updates from this neighbor.",
                    "category": "unitary"
                },
                "prefix_list_in6": {
                    "v_range": [],
                    "type": "string",
                    "name": "prefix-list-in6",
                    "help": "IPv6 Inbound filter for updates from this neighbor.",
                    "category": "unitary"
                },
                "prefix_list_out": {
                    "v_range": [],
                    "type": "string",
                    "name": "prefix-list-out",
                    "help": "IPv4 Outbound filter for updates to this neighbor.",
                    "category": "unitary"
                },
                "prefix_list_out6": {
                    "v_range": [],
                    "type": "string",
                    "name": "prefix-list-out6",
                    "help": "IPv6 Outbound filter for updates to this neighbor.",
                    "category": "unitary"
                },
                "remote_as": {
                    "v_range": [],
                    "type": "string",
                    "name": "remote-as",
                    "help": "AS number of neighbor.",
                    "category": "unitary"
                },
                "route_map_in": {
                    "v_range": [],
                    "type": "string",
                    "name": "route-map-in",
                    "help": "IPv4 Inbound route map filter.",
                    "category": "unitary"
                },
                "route_map_in_evpn": {
                    "v_range": [],
                    "type": "string",
                    "name": "route-map-in-evpn",
                    "help": "EVPN Inbound route map filter.",
                    "category": "unitary"
                },
                "route_map_in6": {
                    "v_range": [],
                    "type": "string",
                    "name": "route-map-in6",
                    "help": "IPv6 Inbound route map filter.",
                    "category": "unitary"
                },
                "route_map_out": {
                    "v_range": [],
                    "type": "string",
                    "name": "route-map-out",
                    "help": "IPv4 outbound route map filter.",
                    "category": "unitary"
                },
                "route_map_out_evpn": {
                    "v_range": [],
                    "type": "string",
                    "name": "route-map-out-evpn",
                    "help": "EVPN outbound route map filter.",
                    "category": "unitary"
                },
                "route_map_out6": {
                    "v_range": [],
                    "type": "string",
                    "name": "route-map-out6",
                    "help": "IPv6 Outbound route map filter.",
                    "category": "unitary"
                },
                "send_community": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "standard"
                        },
                        {
                            "value": "extended"
                        },
                        {
                            "value": "both"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "send-community",
                    "help": "IPv4 Send community attribute to neighbor.",
                    "category": "unitary"
                },
                "send_community6": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {
                            "value": "standard"
                        },
                        {
                            "value": "extended"
                        },
                        {
                            "value": "both"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "send-community6",
                    "help": "IPv6 Send community attribute to neighbor.",
                    "category": "unitary"
                },
                "keep_alive_timer": {
                    "v_range": [],
                    "type": "integer",
                    "name": "keep-alive-timer",
                    "help": "Keepalive timer interval (seconds).",
                    "category": "unitary"
                },
                "holdtime_timer": {
                    "v_range": [],
                    "type": "integer",
                    "name": "holdtime-timer",
                    "help": "Interval (seconds) before peer considered dead.",
                    "category": "unitary"
                },
                "connect_timer": {
                    "v_range": [],
                    "type": "integer",
                    "name": "connect-timer",
                    "help": "Interval (seconds) for connect timer.",
                    "category": "unitary"
                },
                "unsuppress_map": {
                    "v_range": [],
                    "type": "string",
                    "name": "unsuppress-map",
                    "help": "IPv4 Route map to selectively unsuppress suppressed routes.",
                    "category": "unitary"
                },
                "unsuppress_map6": {
                    "v_range": [],
                    "type": "string",
                    "name": "unsuppress-map6",
                    "help": "IPv6 Route map to selectively unsuppress suppressed routes.",
                    "category": "unitary"
                },
                "update_source": {
                    "v_range": [],
                    "type": "string",
                    "name": "update-source",
                    "help": "Interface to use as source IP/IPv6 address of TCP connections.",
                    "category": "unitary"
                },
                "weight": {
                    "v_range": [],
                    "type": "integer",
                    "name": "weight",
                    "help": "Neighbor weight.",
                    "category": "unitary"
                },
                "password": {
                    "v_range": [],
                    "type": "string",
                    "name": "password",
                    "help": "Password used in MD5 authentication.",
                    "category": "unitary"
                }
            },
            "v_range": [],
            "name": "neighbor-group",
            "help": "BGP neighbor group table.",
            "mkey": "name",
            "category": "table"
        }
    },
    "name": "bgp",
    "help": "BGP configuration.",
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
        "router_bgp": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["router_bgp"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["router_bgp"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "router_bgp")
        is_error, has_changed, result, diff = fortiswitch_router(module.params, fos, module.check_mode)
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
