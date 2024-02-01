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
module: fortiswitch_router_route_map
short_description: Route map configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and route_map category.
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
    router_route_map:
        description:
            - Route map configuration.
        default: null
        type: dict
        suboptions:
            comments:
                description:
                    - Description/comments.
                type: str
            name:
                description:
                    - Name.
                required: true
                type: str
            protocol:
                description:
                    - Route-map type.
                type: str
                choices:
                    - 'ospf'
                    - 'ospf6'
                    - 'rip'
                    - 'bgp'
                    - 'isis'
                    - 'zebra'
                    - 'ripng'
                    - 'isis6'
            rule:
                description:
                    - Rule.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - 'permit'
                            - 'deny'
                    id:
                        description:
                            - Rule id.
                        type: int
                    match_as_path:
                        description:
                            - Match BGP AS path list.
                        type: str
                    match_community:
                        description:
                            - Match BGP community list.
                        type: str
                    match_community_exact:
                        description:
                            - Do exact matching of communities.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    match_flags:
                        description:
                            - Match-flags.
                        type: int
                    match_interface:
                        description:
                            - Match interface configuration.
                        type: str
                    match_ip6_address:
                        description:
                            - Match ipv6 address permitted by access-list6 or prefix-list6.
                        type: str
                    match_ip_address:
                        description:
                            - Match ip address permitted by access-list or prefix-list.
                        type: str
                    match_ip_nexthop:
                        description:
                            - Match next hop ip address passed by access-list or prefix-list.
                        type: str
                    match_metric:
                        description:
                            - Match metric for redistribute routes.
                        type: int
                    match_origin:
                        description:
                            - Match BGP origin code.
                        type: str
                        choices:
                            - 'none'
                            - 'egp'
                            - 'igp'
                            - 'incomplete'
                    match_route_type:
                        description:
                            - Match route type.
                        type: str
                        choices:
                            - '1'
                            - '2'
                    match_tag:
                        description:
                            - Match tag.
                        type: int
                    set_aggregator_as:
                        description:
                            - Set BGP aggregator AS.
                        type: int
                    set_aggregator_ip:
                        description:
                            - Set BGP aggregator IP.
                        type: str
                    set_aspath:
                        description:
                            - Prepend BGP AS path attribute.
                        type: list
                        elements: dict
                        suboptions:
                            as:
                                description:
                                    - AS number, value range from 0 to 4294967295
                                type: str
                    set_atomic_aggregate:
                        description:
                            - BGP atomic aggregate attribute.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    set_community:
                        description:
                            - Set BGP community attribute.
                        type: list
                        elements: dict
                        suboptions:
                            community:
                                description:
                                    - 'AA|AA:NN|internet|local-AS|no-advertise|no-export.'
                                type: str
                    set_community_additive:
                        description:
                            - Add set-community to existing community.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    set_community_delete:
                        description:
                            - Delete communities matching community list.
                        type: str
                    set_extcommunity_rt:
                        description:
                            - Set Route Target extended community.
                        type: list
                        elements: dict
                        suboptions:
                            community:
                                description:
                                    - 'AA:NN.'
                                type: str
                    set_extcommunity_soo:
                        description:
                            - Set Site-of-Origin extended community.
                        type: list
                        elements: dict
                        suboptions:
                            community:
                                description:
                                    - 'AA:NN.'
                                type: str
                    set_flags:
                        description:
                            - Set-flags.
                        type: int
                    set_ip6_nexthop:
                        description:
                            - Set ipv6 global address of next hop.
                        type: str
                    set_ip6_nexthop_local:
                        description:
                            - Set ipv6 local address of next hop.
                        type: str
                    set_ip_nexthop:
                        description:
                            - Set ip address of next hop.
                        type: str
                    set_local_preference:
                        description:
                            - Set BGP local preference path attribute.
                        type: int
                    set_metric:
                        description:
                            - Set the metric value.
                        type: int
                    set_metric_type:
                        description:
                            - Set the metric type.
                        type: str
                        choices:
                            - '1'
                            - '2'
                    set_origin:
                        description:
                            - Set BGP origin code.
                        type: str
                        choices:
                            - 'none'
                            - 'egp'
                            - 'igp'
                            - 'incomplete'
                    set_originator_id:
                        description:
                            - Set BGP originator ID attribute.
                        type: str
                    set_tag:
                        description:
                            - Set the tag value.
                        type: int
                    set_weight:
                        description:
                            - Set BGP weight for routing table.
                        type: int
'''

EXAMPLES = '''
- name: Route map configuration.
  fortinet.fortiswitch.fortiswitch_router_route_map:
      state: "present"
      router_route_map:
          comments: "<your_own_value>"
          name: "default_name_4"
          protocol: "ospf"
          rule:
              -
                  action: "permit"
                  id: "8"
                  match_as_path: "<your_own_value> (source router.aspath-list.name)"
                  match_community: "<your_own_value> (source router.community-list.name)"
                  match_community_exact: "enable"
                  match_flags: "12"
                  match_interface: "<your_own_value> (source system.interface.name)"
                  match_ip6_address: "<your_own_value> (source router.access-list6.name router.prefix-list6.name)"
                  match_ip_address: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
                  match_ip_nexthop: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
                  match_metric: "17"
                  match_origin: "none"
                  match_route_type: "1"
                  match_tag: "20"
                  set_aggregator_as: "21"
                  set_aggregator_ip: "<your_own_value>"
                  set_aspath:
                      -
                          as: "<your_own_value>"
                  set_atomic_aggregate: "enable"
                  set_community:
                      -
                          community: "<your_own_value>"
                  set_community_additive: "enable"
                  set_community_delete: "<your_own_value> (source router.community-list.name)"
                  set_extcommunity_rt:
                      -
                          community: "<your_own_value>"
                  set_extcommunity_soo:
                      -
                          community: "<your_own_value>"
                  set_flags: "34"
                  set_ip6_nexthop: "<your_own_value>"
                  set_ip6_nexthop_local: "<your_own_value>"
                  set_ip_nexthop: "<your_own_value>"
                  set_local_preference: "38"
                  set_metric: "39"
                  set_metric_type: "1"
                  set_origin: "none"
                  set_originator_id: "<your_own_value>"
                  set_tag: "43"
                  set_weight: "44"
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


def filter_router_route_map_data(json):
    option_list = ['comments', 'name', 'protocol',
                   'rule']

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


def router_route_map(data, fos, check_mode=False):
    state = data['state']
    router_route_map_data = data['router_route_map']
    filtered_data = underscore_to_hyphen(filter_router_route_map_data(router_route_map_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('router', 'route-map', filtered_data)
        current_data = fos.get('router', 'route-map', mkey=mkey)
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
        return fos.set('router',
                       'route-map',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('router',
                          'route-map',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_router(data, fos, check_mode):
    fos.do_member_operation('router', 'route-map')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['router_route_map']:
        resp = router_route_map(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('router_route_map'))
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
        "rule": {
            "type": "list",
            "elements": "dict",
            "children": {
                "match_community_exact": {
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
                    "name": "match-community-exact",
                    "help": "Do exact matching of communities.",
                    "category": "unitary"
                },
                "set_community": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "community": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "name": "community",
                            "help": "AA|AA:NN|internet|local-AS|no-advertise|no-export.",
                            "category": "unitary"
                        }
                    },
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "name": "set-community",
                    "help": "Set BGP community attribute.",
                    "mkey": "community",
                    "category": "table"
                },
                "set_metric": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "set-metric",
                    "help": "Set the metric value.",
                    "category": "unitary"
                },
                "set_atomic_aggregate": {
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
                    "name": "set-atomic-aggregate",
                    "help": "BGP atomic aggregate attribute.",
                    "category": "unitary"
                },
                "match_ip6_address": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "match-ip6-address",
                    "help": "Match ipv6 address permitted by access-list6 or prefix-list6.",
                    "category": "unitary"
                },
                "match_origin": {
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
                            "value": "egp"
                        },
                        {
                            "value": "igp"
                        },
                        {
                            "value": "incomplete"
                        }
                    ],
                    "name": "match-origin",
                    "help": "Match BGP origin code.",
                    "category": "unitary"
                },
                "match_metric": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "match-metric",
                    "help": "Match metric for redistribute routes.",
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
                    "help": "Rule id.",
                    "category": "unitary"
                },
                "match_flags": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "match-flags",
                    "help": "Match-flags.",
                    "category": "unitary"
                },
                "match_ip_address": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "match-ip-address",
                    "help": "Match ip address permitted by access-list or prefix-list.",
                    "category": "unitary"
                },
                "set_origin": {
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
                            "value": "egp"
                        },
                        {
                            "value": "igp"
                        },
                        {
                            "value": "incomplete"
                        }
                    ],
                    "name": "set-origin",
                    "help": "Set BGP origin code.",
                    "category": "unitary"
                },
                "set_extcommunity_soo": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "community": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "name": "community",
                            "help": "AA:NN.",
                            "category": "unitary"
                        }
                    },
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "name": "set-extcommunity-soo",
                    "help": "Set Site-of-Origin extended community.",
                    "mkey": "community",
                    "category": "table"
                },
                "set_flags": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "set-flags",
                    "help": "Set-flags.",
                    "category": "unitary"
                },
                "set_ip6_nexthop": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "set-ip6-nexthop",
                    "help": "Set ipv6 global address of next hop.",
                    "category": "unitary"
                },
                "match_as_path": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "match-as-path",
                    "help": "Match BGP AS path list.",
                    "category": "unitary"
                },
                "set_extcommunity_rt": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "community": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "name": "community",
                            "help": "AA:NN.",
                            "category": "unitary"
                        }
                    },
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "name": "set-extcommunity-rt",
                    "help": "Set Route Target extended community.",
                    "mkey": "community",
                    "category": "table"
                },
                "set_ip_nexthop": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "set-ip-nexthop",
                    "help": "Set ip address of next hop.",
                    "category": "unitary"
                },
                "set_tag": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "set-tag",
                    "help": "Set the tag value.",
                    "category": "unitary"
                },
                "set_aggregator_as": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "set-aggregator-as",
                    "help": "Set BGP aggregator AS.",
                    "category": "unitary"
                },
                "set_weight": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "set-weight",
                    "help": "Set BGP weight for routing table.",
                    "category": "unitary"
                },
                "match_route_type": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "1"
                        },
                        {
                            "value": "2"
                        }
                    ],
                    "name": "match-route-type",
                    "help": "Match route type.",
                    "category": "unitary"
                },
                "set_community_delete": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "set-community-delete",
                    "help": "Delete communities matching community list.",
                    "category": "unitary"
                },
                "match_community": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "match-community",
                    "help": "Match BGP community list.",
                    "category": "unitary"
                },
                "set_metric_type": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "1"
                        },
                        {
                            "value": "2"
                        }
                    ],
                    "name": "set-metric-type",
                    "help": "Set the metric type.",
                    "category": "unitary"
                },
                "set_community_additive": {
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
                    "name": "set-community-additive",
                    "help": "Add set-community to existing community.",
                    "category": "unitary"
                },
                "match_ip_nexthop": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "match-ip-nexthop",
                    "help": "Match next hop ip address passed by access-list or prefix-list.",
                    "category": "unitary"
                },
                "set_originator_id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "set-originator-id",
                    "help": "Set BGP originator ID attribute.",
                    "category": "unitary"
                },
                "match_tag": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "match-tag",
                    "help": "Match tag.",
                    "category": "unitary"
                },
                "set_aggregator_ip": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "set-aggregator-ip",
                    "help": "Set BGP aggregator IP.",
                    "category": "unitary"
                },
                "match_interface": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "match-interface",
                    "help": "Match interface configuration.",
                    "category": "unitary"
                },
                "set_aspath": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "as": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "name": "as",
                            "help": "AS number,value range from 0 to 4294967295",
                            "category": "unitary"
                        }
                    },
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "name": "set-aspath",
                    "help": "Prepend BGP AS path attribute.",
                    "mkey": "as",
                    "category": "table"
                },
                "action": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "permit"
                        },
                        {
                            "value": "deny"
                        }
                    ],
                    "name": "action",
                    "help": "Action.",
                    "category": "unitary"
                },
                "set_ip6_nexthop_local": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "set-ip6-nexthop-local",
                    "help": "Set ipv6 local address of next hop.",
                    "category": "unitary"
                },
                "set_local_preference": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "set-local-preference",
                    "help": "Set BGP local preference path attribute.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "rule",
            "help": "Rule.",
            "mkey": "id",
            "category": "table"
        },
        "protocol": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "ospf"
                },
                {
                    "value": "ospf6"
                },
                {
                    "value": "rip"
                },
                {
                    "value": "bgp"
                },
                {
                    "value": "isis"
                },
                {
                    "value": "zebra"
                },
                {
                    "value": "ripng"
                },
                {
                    "value": "isis6"
                }
            ],
            "name": "protocol",
            "help": "Route-map type.",
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
        "comments": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "comments",
            "help": "Description/comments.",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "name": "route-map",
    "help": "Route map configuration.",
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
        "router_route_map": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["router_route_map"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["router_route_map"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "router_route_map")
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
