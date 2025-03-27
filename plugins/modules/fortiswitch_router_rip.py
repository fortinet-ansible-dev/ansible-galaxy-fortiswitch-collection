#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortiswitch_router_rip
short_description: RIP configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and rip category.
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

    router_rip:
        description:
            - RIP configuration.
        default: null
        type: dict
        suboptions:
            bfd:
                description:
                    - Bidirectional Forwarding Detection (BFD).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_information_originate:
                description:
                    - Generate a default route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_metric:
                description:
                    - Default metric of redistribute routes (Except connected).
                type: int
            distance:
                description:
                    - Set admin distance based on route source ip.
                type: list
                elements: dict
                suboptions:
                    access_list:
                        description:
                            - Access list for route destination.
                        type: str
                    distance:
                        description:
                            - Distance.
                        type: int
                    id:
                        description:
                            - Distance id.
                        type: int
                    prefix:
                        description:
                            - IP source prefix.
                        type: str
            distribute_list:
                description:
                    - Filter networks in routing updates.
                type: list
                elements: dict
                suboptions:
                    direction:
                        description:
                            - Distribute list direction.
                        type: str
                        choices:
                            - 'in'
                            - 'out'
                    id:
                        description:
                            - Distribute-list id.
                        type: int
                    interface:
                        description:
                            - Distribute list interface name.
                        type: str
                    listname:
                        description:
                            - Distribute access/prefix list name.
                        type: str
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            garbage_timer:
                description:
                    - Garbage collection timer.
                type: int
            interface:
                description:
                    - RIP interface configuration
                type: list
                elements: dict
                suboptions:
                    auth_keychain:
                        description:
                            - Authentication keychain name.
                        type: str
                    auth_mode:
                        description:
                            - Authentication mode.
                        type: str
                        choices:
                            - 'none'
                            - 'text'
                            - 'md5'
                    auth_string:
                        description:
                            - Authentication string/password.
                        type: str
                    bfd:
                        description:
                            - Bidirectional Forwarding Detection (BFD).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    flags:
                        description:
                            - flags
                        type: int
                    name:
                        description:
                            - interface name
                        type: str
                    receive_version:
                        description:
                            - Receive version.
                        type: str
                        choices:
                            - 'global'
                            - '1'
                            - '2'
                            - 'both'
                    send_version:
                        description:
                            - Send version.
                        type: str
                        choices:
                            - 'global'
                            - '1'
                            - '2'
                            - 'both'
                    send_version2_broadcast:
                        description:
                            - broadcast version 1 compatible packets
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    split_horizon:
                        description:
                            - Split horizon method.
                        type: str
                        choices:
                            - 'poisoned'
                            - 'regular'
                    split_horizon_status:
                        description:
                            - Split horizon status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            name:
                description:
                    - Vrf name.
                type: str
            neighbor:
                description:
                    - Specify a neighbor router. Required only for non-multicast networks.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Neighbor entry id.
                        type: int
                    ip:
                        description:
                            - IP address.
                        type: str
            network:
                description:
                    - Enable RIP routing on an IP network.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Network entry id.
                        type: int
                    prefix:
                        description:
                            - Network prefix.
                        type: str
            offset_list:
                description:
                    - Offset list to modify RIP metric.
                type: list
                elements: dict
                suboptions:
                    access_list:
                        description:
                            - Access list name.
                        type: str
                    direction:
                        description:
                            - Offset list direction.
                        type: str
                        choices:
                            - 'in'
                            - 'out'
                    id:
                        description:
                            - Offset-list id.
                        type: int
                    interface:
                        description:
                            - Interface to match.
                        type: str
                    offset:
                        description:
                            - Metric value.
                        type: int
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
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
            recv_buffer_size:
                description:
                    - receiving buffer size
                type: int
            redistribute:
                description:
                    - Redistribute configuration.
                type: list
                elements: dict
                suboptions:
                    flags:
                        description:
                            - flags
                        type: int
                    metric:
                        description:
                            - Redistribute metric setting.
                        type: int
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
            timeout_timer:
                description:
                    - Routing information timeout timer.
                type: int
            update_timer:
                description:
                    - Routing table update timer.
                type: int
            version:
                description:
                    - RIP version
                type: str
                choices:
                    - '1'
                    - '2'
            vrf:
                description:
                    - Enable RIP on VRF.
                type: list
                elements: dict
                suboptions:
                    default_information_originate:
                        description:
                            - Generate a default route.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    default_metric:
                        description:
                            - Default metric of redistribute routes (Except connected).
                        type: int
                    distance:
                        description:
                            - Set admin distance based on route source ip.
                        type: list
                        elements: dict
                        suboptions:
                            access_list:
                                description:
                                    - Access list for route destination.
                                type: str
                            distance:
                                description:
                                    - Distance.
                                type: int
                            id:
                                description:
                                    - Distance id.
                                type: int
                            prefix:
                                description:
                                    - IP source prefix.
                                type: str
                    distribute_list:
                        description:
                            - Filter networks in routing updates.
                        type: list
                        elements: dict
                        suboptions:
                            direction:
                                description:
                                    - Distribute list direction.
                                type: str
                                choices:
                                    - 'in'
                                    - 'out'
                            id:
                                description:
                                    - Distribute-list id.
                                type: int
                            interface:
                                description:
                                    - Distribute list interface name.
                                type: str
                            listname:
                                description:
                                    - Distribute access/prefix list name.
                                type: str
                            status:
                                description:
                                    - Status.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    garbage_timer:
                        description:
                            - Garbage collection timer.
                        type: int
                    interface:
                        description:
                            - RIP interface configuration
                        type: list
                        elements: dict
                        suboptions:
                            auth_keychain:
                                description:
                                    - Authentication keychain name.
                                type: str
                            auth_mode:
                                description:
                                    - Authentication mode.
                                type: str
                                choices:
                                    - 'none'
                                    - 'text'
                                    - 'md5'
                            auth_string:
                                description:
                                    - Authentication string/password.
                                type: str
                            flags:
                                description:
                                    - flags
                                type: int
                            name:
                                description:
                                    - interface name
                                type: str
                            receive_version:
                                description:
                                    - Receive version.
                                type: str
                                choices:
                                    - 'global'
                                    - '1'
                                    - '2'
                                    - 'both'
                            send_version:
                                description:
                                    - Send version.
                                type: str
                                choices:
                                    - 'global'
                                    - '1'
                                    - '2'
                                    - 'both'
                            send_version2_broadcast:
                                description:
                                    - broadcast version 1 compatible packets
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            split_horizon:
                                description:
                                    - Split horizon method.
                                type: str
                                choices:
                                    - 'poisoned'
                                    - 'regular'
                            split_horizon_status:
                                description:
                                    - Split horizon status.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    name:
                        description:
                            - Vrf name.
                        type: str
                    neighbor:
                        description:
                            - Specify a neighbor router. Required only for non-multicast networks.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Neighbor entry id.
                                type: int
                            ip:
                                description:
                                    - IP address.
                                type: str
                    network:
                        description:
                            - Enable RIP routing on an IP network.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Network entry id.
                                type: int
                            prefix:
                                description:
                                    - Network prefix.
                                type: str
                    offset_list:
                        description:
                            - Offset list to modify RIP metric.
                        type: list
                        elements: dict
                        suboptions:
                            access_list:
                                description:
                                    - Access list name.
                                type: str
                            direction:
                                description:
                                    - Offset list direction.
                                type: str
                                choices:
                                    - 'in'
                                    - 'out'
                            id:
                                description:
                                    - Offset-list id.
                                type: int
                            interface:
                                description:
                                    - Interface to match.
                                type: str
                            offset:
                                description:
                                    - Metric value.
                                type: int
                            status:
                                description:
                                    - Status.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
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
                    recv_buffer_size:
                        description:
                            - receiving buffer size
                        type: int
                    redistribute:
                        description:
                            - Redistribute configuration.
                        type: list
                        elements: dict
                        suboptions:
                            flags:
                                description:
                                    - flags
                                type: int
                            metric:
                                description:
                                    - Redistribute metric setting.
                                type: int
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
                    timeout_timer:
                        description:
                            - Routing information timeout timer.
                        type: int
                    update_timer:
                        description:
                            - Routing table update timer.
                        type: int
                    version:
                        description:
                            - RIP version
                        type: str
                        choices:
                            - '1'
                            - '2'
"""

EXAMPLES = """
- name: RIP configuration.
  fortinet.fortiswitch.fortiswitch_router_rip:
      router_rip:
          bfd: "enable"
          default_information_originate: "enable"
          default_metric: "5"
          distance:
              -
                  access_list: "<your_own_value> (source router.access-list.name)"
                  distance: "8"
                  id: "9"
                  prefix: "<your_own_value>"
          distribute_list:
              -
                  direction: "in"
                  id: "13"
                  interface: "<your_own_value> (source system.interface.name)"
                  listname: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
                  status: "enable"
          garbage_timer: "17"
          interface:
              -
                  auth_keychain: "<your_own_value> (source router.key-chain.name)"
                  auth_mode: "none"
                  auth_string: "<your_own_value>"
                  bfd: "enable"
                  flags: "23"
                  name: "default_name_24 (source system.interface.name)"
                  receive_version: "global"
                  send_version: "global"
                  send_version2_broadcast: "disable"
                  split_horizon: "poisoned"
                  split_horizon_status: "enable"
          name: "default_name_30"
          neighbor:
              -
                  id: "32"
                  ip: "<your_own_value>"
          network:
              -
                  id: "35"
                  prefix: "<your_own_value>"
          offset_list:
              -
                  access_list: "<your_own_value> (source router.access-list.name)"
                  direction: "in"
                  id: "40"
                  interface: "<your_own_value> (source system.interface.name)"
                  offset: "42"
                  status: "enable"
          passive_interface:
              -
                  name: "default_name_45 (source system.interface.name)"
          recv_buffer_size: "1073741823"
          redistribute:
              -
                  flags: "48"
                  metric: "49"
                  name: "default_name_50"
                  routemap: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          timeout_timer: "53"
          update_timer: "54"
          version: "1"
          vrf:
              -
                  default_information_originate: "enable"
                  default_metric: "58"
                  distance:
                      -
                          access_list: "<your_own_value> (source router.access-list.name)"
                          distance: "61"
                          id: "62"
                          prefix: "<your_own_value>"
                  distribute_list:
                      -
                          direction: "in"
                          id: "66"
                          interface: "<your_own_value> (source system.interface.name)"
                          listname: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
                          status: "enable"
                  garbage_timer: "70"
                  interface:
                      -
                          auth_keychain: "<your_own_value> (source router.key-chain.name)"
                          auth_mode: "none"
                          auth_string: "<your_own_value>"
                          flags: "75"
                          name: "default_name_76 (source system.interface.name)"
                          receive_version: "global"
                          send_version: "global"
                          send_version2_broadcast: "disable"
                          split_horizon: "poisoned"
                          split_horizon_status: "enable"
                  name: "default_name_82 (source router.vrf.name)"
                  neighbor:
                      -
                          id: "84"
                          ip: "<your_own_value>"
                  network:
                      -
                          id: "87"
                          prefix: "<your_own_value>"
                  offset_list:
                      -
                          access_list: "<your_own_value> (source router.access-list.name)"
                          direction: "in"
                          id: "92"
                          interface: "<your_own_value> (source system.interface.name)"
                          offset: "94"
                          status: "enable"
                  passive_interface:
                      -
                          name: "default_name_97 (source system.interface.name)"
                  recv_buffer_size: "1073741823"
                  redistribute:
                      -
                          flags: "100"
                          metric: "101"
                          name: "default_name_102"
                          routemap: "<your_own_value> (source router.route-map.name)"
                          status: "enable"
                  timeout_timer: "105"
                  update_timer: "106"
                  version: "1"
"""

RETURN = """
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

"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import (
    find_current_values,
)


def filter_router_rip_data(json):
    option_list = [
        "bfd",
        "default_information_originate",
        "default_metric",
        "distance",
        "distribute_list",
        "garbage_timer",
        "interface",
        "name",
        "neighbor",
        "network",
        "offset_list",
        "passive_interface",
        "recv_buffer_size",
        "redistribute",
        "timeout_timer",
        "update_timer",
        "version",
        "vrf",
    ]

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
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data


def router_rip(data, fos, check_mode=False):
    state = data.get("state", None)

    router_rip_data = data["router_rip"]

    filtered_data = filter_router_rip_data(router_rip_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("router", "rip", filtered_data)
        current_data = fos.get("router", "rip", mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and isinstance(current_data.get("results"), list)
            and len(current_data["results"]) > 0
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
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
                    serialize(current_data["results"]), serialize(copied_filtered_data)
                )

                current_values = find_current_values(
                    copied_filtered_data, current_data["results"]
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": copied_filtered_data},
                )

            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]),
                    serialize(copied_filtered_data),
                )

                current_values = find_current_values(
                    copied_filtered_data, current_data["results"][0]
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": copied_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}

    return fos.set(
        "router",
        "rip",
        data=filtered_data,
    )


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortiswitch_router(data, fos, check_mode):
    fos.do_member_operation("router", "rip")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["router_rip"]:
        resp = router_rip(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_rip"))
    if check_mode:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp) and current_cmdb_index != resp["cmdb-index"],
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v7.0.0", ""]],
    "type": "dict",
    "children": {
        "distance": {
            "type": "list",
            "elements": "dict",
            "children": {
                "access_list": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "access-list",
                    "help": "Access list for route destination.",
                    "category": "unitary",
                },
                "distance": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "distance",
                    "help": "Distance.",
                    "category": "unitary",
                },
                "prefix": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "prefix",
                    "help": "IP source prefix.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Distance id.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "distance",
            "help": "Set admin distance based on route source ip.",
            "mkey": "id",
            "category": "table",
        },
        "default_metric": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "default-metric",
            "help": "Default metric of redistribute routes (Except connected).",
            "category": "unitary",
        },
        "recv_buffer_size": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "recv-buffer-size",
            "help": "receiving buffer size",
            "category": "unitary",
        },
        "timeout_timer": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "timeout-timer",
            "help": "Routing information timeout timer.",
            "category": "unitary",
        },
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "Vrf name.",
            "category": "unitary",
        },
        "bfd": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "bfd",
            "help": "Bidirectional Forwarding Detection (BFD).",
            "category": "unitary",
        },
        "offset_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "status",
                    "help": "Status.",
                    "category": "unitary",
                },
                "direction": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "in"}, {"value": "out"}],
                    "name": "direction",
                    "help": "Offset list direction.",
                    "category": "unitary",
                },
                "interface": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "interface",
                    "help": "Interface to match.",
                    "category": "unitary",
                },
                "offset": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "offset",
                    "help": "Metric value.",
                    "category": "unitary",
                },
                "access_list": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "access-list",
                    "help": "Access list name.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Offset-list id.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "offset-list",
            "help": "Offset list to modify RIP metric.",
            "mkey": "id",
            "category": "table",
        },
        "redistribute": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "status",
                    "help": "status",
                    "category": "unitary",
                },
                "metric": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "metric",
                    "help": "Redistribute metric setting.",
                    "category": "unitary",
                },
                "routemap": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "routemap",
                    "help": "Route map name.",
                    "category": "unitary",
                },
                "flags": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "flags",
                    "help": "flags",
                    "category": "unitary",
                },
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Redistribute name.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "redistribute",
            "help": "Redistribute configuration.",
            "mkey": "name",
            "category": "table",
        },
        "neighbor": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {
                    "v_range": [["v7.0.0", "v7.0.0"]],
                    "type": "string",
                    "name": "ip",
                    "help": "IP address.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", "v7.0.0"]],
                    "type": "integer",
                    "name": "id",
                    "help": "Neighbor entry id.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", "v7.0.0"]],
            "name": "neighbor",
            "help": "Specify a neighbor router. Required only for non-multicast networks.",
            "mkey": "id",
            "category": "table",
        },
        "version": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "1"}, {"value": "2"}],
            "name": "version",
            "help": "RIP version",
            "category": "unitary",
        },
        "garbage_timer": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "garbage-timer",
            "help": "Garbage collection timer.",
            "category": "unitary",
        },
        "vrf": {
            "type": "list",
            "elements": "dict",
            "children": {
                "distance": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "access_list": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "access-list",
                            "help": "Access list for route destination.",
                            "category": "unitary",
                        },
                        "distance": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "distance",
                            "help": "Distance.",
                            "category": "unitary",
                        },
                        "prefix": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "prefix",
                            "help": "IP source prefix.",
                            "category": "unitary",
                        },
                        "id": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "id",
                            "help": "Distance id.",
                            "category": "unitary",
                        },
                    },
                    "v_range": [["v7.0.0", ""]],
                    "name": "distance",
                    "help": "Set admin distance based on route source ip.",
                    "mkey": "id",
                    "category": "table",
                },
                "default_metric": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "default-metric",
                    "help": "Default metric of redistribute routes (Except connected).",
                    "category": "unitary",
                },
                "recv_buffer_size": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "recv-buffer-size",
                    "help": "receiving buffer size",
                    "category": "unitary",
                },
                "timeout_timer": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "timeout-timer",
                    "help": "Routing information timeout timer.",
                    "category": "unitary",
                },
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Vrf name.",
                    "category": "unitary",
                },
                "offset_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                            "name": "status",
                            "help": "Status.",
                            "category": "unitary",
                        },
                        "direction": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "in"}, {"value": "out"}],
                            "name": "direction",
                            "help": "Offset list direction.",
                            "category": "unitary",
                        },
                        "interface": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "interface",
                            "help": "Interface to match.",
                            "category": "unitary",
                        },
                        "offset": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "offset",
                            "help": "Metric value.",
                            "category": "unitary",
                        },
                        "access_list": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "access-list",
                            "help": "Access list name.",
                            "category": "unitary",
                        },
                        "id": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "id",
                            "help": "Offset-list id.",
                            "category": "unitary",
                        },
                    },
                    "v_range": [["v7.0.0", ""]],
                    "name": "offset-list",
                    "help": "Offset list to modify RIP metric.",
                    "mkey": "id",
                    "category": "table",
                },
                "redistribute": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                            "name": "status",
                            "help": "status",
                            "category": "unitary",
                        },
                        "metric": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "metric",
                            "help": "Redistribute metric setting.",
                            "category": "unitary",
                        },
                        "routemap": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "routemap",
                            "help": "Route map name.",
                            "category": "unitary",
                        },
                        "flags": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "flags",
                            "help": "flags",
                            "category": "unitary",
                        },
                        "name": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "name",
                            "help": "Redistribute name.",
                            "category": "unitary",
                        },
                    },
                    "v_range": [["v7.0.0", ""]],
                    "name": "redistribute",
                    "help": "Redistribute configuration.",
                    "mkey": "name",
                    "category": "table",
                },
                "neighbor": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "ip": {
                            "v_range": [["v7.0.0", "v7.0.0"]],
                            "type": "string",
                            "name": "ip",
                            "help": "IP address.",
                            "category": "unitary",
                        },
                        "id": {
                            "v_range": [["v7.0.0", "v7.0.0"]],
                            "type": "integer",
                            "name": "id",
                            "help": "Neighbor entry id.",
                            "category": "unitary",
                        },
                    },
                    "v_range": [["v7.0.0", "v7.0.0"]],
                    "name": "neighbor",
                    "help": "Specify a neighbor router. Required only for non-multicast networks.",
                    "mkey": "id",
                    "category": "table",
                },
                "version": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "1"}, {"value": "2"}],
                    "name": "version",
                    "help": "RIP version",
                    "category": "unitary",
                },
                "garbage_timer": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "garbage-timer",
                    "help": "Garbage collection timer.",
                    "category": "unitary",
                },
                "default_information_originate": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "default-information-originate",
                    "help": "Generate a default route.",
                    "category": "unitary",
                },
                "passive_interface": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "name",
                            "help": "Passive interface name.",
                            "category": "unitary",
                        }
                    },
                    "v_range": [["v7.0.0", ""]],
                    "name": "passive-interface",
                    "help": "Passive interface configuration.",
                    "mkey": "name",
                    "category": "table",
                },
                "update_timer": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "update-timer",
                    "help": "Routing table update timer.",
                    "category": "unitary",
                },
                "interface": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "split_horizon_status": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                            "name": "split-horizon-status",
                            "help": "Split horizon status.",
                            "category": "unitary",
                        },
                        "auth_mode": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "none"},
                                {"value": "text"},
                                {"value": "md5"},
                            ],
                            "name": "auth-mode",
                            "help": "Authentication mode.",
                            "category": "unitary",
                        },
                        "name": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "name",
                            "help": "interface name",
                            "category": "unitary",
                        },
                        "send_version2_broadcast": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                            "name": "send-version2-broadcast",
                            "help": "broadcast version 1 compatible packets",
                            "category": "unitary",
                        },
                        "send_version": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "global"},
                                {"value": "1"},
                                {"value": "2"},
                                {"value": "both"},
                            ],
                            "name": "send-version",
                            "help": "Send version.",
                            "category": "unitary",
                        },
                        "auth_keychain": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "auth-keychain",
                            "help": "Authentication keychain name.",
                            "category": "unitary",
                        },
                        "split_horizon": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "poisoned"}, {"value": "regular"}],
                            "name": "split-horizon",
                            "help": "Split horizon method.",
                            "category": "unitary",
                        },
                        "flags": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "flags",
                            "help": "flags",
                            "category": "unitary",
                        },
                        "auth_string": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "auth-string",
                            "help": "Authentication string/password.",
                            "category": "unitary",
                        },
                        "receive_version": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "global"},
                                {"value": "1"},
                                {"value": "2"},
                                {"value": "both"},
                            ],
                            "name": "receive-version",
                            "help": "Receive version.",
                            "category": "unitary",
                        },
                    },
                    "v_range": [["v7.0.0", ""]],
                    "name": "interface",
                    "help": "RIP interface configuration",
                    "mkey": "name",
                    "category": "table",
                },
                "distribute_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                            "name": "status",
                            "help": "Status.",
                            "category": "unitary",
                        },
                        "listname": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "listname",
                            "help": "Distribute access/prefix list name.",
                            "category": "unitary",
                        },
                        "direction": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "in"}, {"value": "out"}],
                            "name": "direction",
                            "help": "Distribute list direction.",
                            "category": "unitary",
                        },
                        "interface": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "interface",
                            "help": "Distribute list interface name.",
                            "category": "unitary",
                        },
                        "id": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "id",
                            "help": "Distribute-list id.",
                            "category": "unitary",
                        },
                    },
                    "v_range": [["v7.0.0", ""]],
                    "name": "distribute-list",
                    "help": "Filter networks in routing updates.",
                    "mkey": "id",
                    "category": "table",
                },
                "network": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "prefix": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "prefix",
                            "help": "Network prefix.",
                            "category": "unitary",
                        },
                        "id": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "id",
                            "help": "Network entry id.",
                            "category": "unitary",
                        },
                    },
                    "v_range": [["v7.0.0", ""]],
                    "name": "network",
                    "help": "Enable RIP routing on an IP network.",
                    "mkey": "id",
                    "category": "table",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "vrf",
            "help": "Enable RIP on VRF.",
            "mkey": "name",
            "category": "table",
        },
        "default_information_originate": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "default-information-originate",
            "help": "Generate a default route.",
            "category": "unitary",
        },
        "passive_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Passive interface name.",
                    "category": "unitary",
                }
            },
            "v_range": [["v7.0.0", ""]],
            "name": "passive-interface",
            "help": "Passive interface configuration.",
            "mkey": "name",
            "category": "table",
        },
        "update_timer": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "update-timer",
            "help": "Routing table update timer.",
            "category": "unitary",
        },
        "interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "split_horizon_status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "split-horizon-status",
                    "help": "Split horizon status.",
                    "category": "unitary",
                },
                "auth_mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "text"}, {"value": "md5"}],
                    "name": "auth-mode",
                    "help": "Authentication mode.",
                    "category": "unitary",
                },
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "interface name",
                    "category": "unitary",
                },
                "send_version2_broadcast": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "send-version2-broadcast",
                    "help": "broadcast version 1 compatible packets",
                    "category": "unitary",
                },
                "send_version": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "global"},
                        {"value": "1"},
                        {"value": "2"},
                        {"value": "both"},
                    ],
                    "name": "send-version",
                    "help": "Send version.",
                    "category": "unitary",
                },
                "auth_keychain": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "auth-keychain",
                    "help": "Authentication keychain name.",
                    "category": "unitary",
                },
                "split_horizon": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "poisoned"}, {"value": "regular"}],
                    "name": "split-horizon",
                    "help": "Split horizon method.",
                    "category": "unitary",
                },
                "flags": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "flags",
                    "help": "flags",
                    "category": "unitary",
                },
                "auth_string": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "auth-string",
                    "help": "Authentication string/password.",
                    "category": "unitary",
                },
                "receive_version": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "global"},
                        {"value": "1"},
                        {"value": "2"},
                        {"value": "both"},
                    ],
                    "name": "receive-version",
                    "help": "Receive version.",
                    "category": "unitary",
                },
                "bfd": {
                    "v_range": [],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "bfd",
                    "help": "Bidirectional Forwarding Detection (BFD).",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "interface",
            "help": "RIP interface configuration",
            "mkey": "name",
            "category": "table",
        },
        "distribute_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "status",
                    "help": "Status.",
                    "category": "unitary",
                },
                "listname": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "listname",
                    "help": "Distribute access/prefix list name.",
                    "category": "unitary",
                },
                "direction": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "in"}, {"value": "out"}],
                    "name": "direction",
                    "help": "Distribute list direction.",
                    "category": "unitary",
                },
                "interface": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "interface",
                    "help": "Distribute list interface name.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Distribute-list id.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "distribute-list",
            "help": "Filter networks in routing updates.",
            "mkey": "id",
            "category": "table",
        },
        "network": {
            "type": "list",
            "elements": "dict",
            "children": {
                "prefix": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "prefix",
                    "help": "Network prefix.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Network entry id.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "network",
            "help": "Enable RIP routing on an IP network.",
            "mkey": "id",
            "category": "table",
        },
    },
    "name": "rip",
    "help": "RIP configuration.",
    "category": "complex",
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = versioned_schema["mkey"] if "mkey" in versioned_schema else None
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "router_rip": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_rip"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_rip"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "router_rip"
        )
        is_error, has_changed, result, diff = fortiswitch_router(
            module.params, fos, module.check_mode
        )
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortiSwitch system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
