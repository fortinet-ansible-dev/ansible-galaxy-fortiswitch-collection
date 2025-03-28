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
module: fortiswitch_router_ripng
short_description: router ripng configuratio in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and ripng category.
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

    router_ripng:
        description:
            - router ripng configuration
        default: null
        type: dict
        suboptions:
            aggregate_address:
                description:
                    - Set aggregate RIPng route announcement.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Aggregate-address entry id.
                        type: int
                    prefix6:
                        description:
                            - Aggregate-address prefix.
                        type: str
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
                    - RIPng interface configuration.
                type: list
                elements: dict
                suboptions:
                    flags:
                        description:
                            - Flags.
                        type: int
                    name:
                        description:
                            - Interface name.
                        type: str
                    passive:
                        description:
                            - Suppress routing updates on an interface.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    split_horizon:
                        description:
                            - Split horizon type.
                        type: str
                        choices:
                            - 'poisoned'
                            - 'regular'
                    split_horizon_status:
                        description:
                            - Enable/disable split horizon.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            offset_list:
                description:
                    - Offset list to modify RIPng metric.
                type: list
                elements: dict
                suboptions:
                    access_list6:
                        description:
                            - Ipv6 access list name.
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
                            - Interface name.
                        type: str
                    offset:
                        description:
                            - Metric offset.
                        type: int
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            redistribute:
                description:
                    - Redistribute configuration.
                type: list
                elements: dict
                suboptions:
                    flags:
                        description:
                            - Flags
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
"""

EXAMPLES = """
- name: router ripng configuration
  fortinet.fortiswitch.fortiswitch_router_ripng:
      router_ripng:
          aggregate_address:
              -
                  id: "4"
                  prefix6: "<your_own_value>"
          bfd: "enable"
          default_information_originate: "enable"
          default_metric: "8"
          distribute_list:
              -
                  direction: "in"
                  id: "11"
                  interface: "<your_own_value> (source system.interface.name)"
                  listname: "<your_own_value> (source router.access-list6.name router.prefix-list6.name)"
                  status: "enable"
          garbage_timer: "15"
          interface:
              -
                  flags: "17"
                  name: "default_name_18 (source system.interface.name)"
                  passive: "enable"
                  split_horizon: "poisoned"
                  split_horizon_status: "enable"
          offset_list:
              -
                  access_list6: "<your_own_value> (source router.access-list6.name)"
                  direction: "in"
                  id: "25"
                  interface: "<your_own_value> (source system.interface.name)"
                  offset: "27"
                  status: "enable"
          redistribute:
              -
                  flags: "30"
                  metric: "31"
                  name: "default_name_32"
                  routemap: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          timeout_timer: "35"
          update_timer: "36"
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


def filter_router_ripng_data(json):
    option_list = [
        "aggregate_address",
        "bfd",
        "default_information_originate",
        "default_metric",
        "distribute_list",
        "garbage_timer",
        "interface",
        "offset_list",
        "redistribute",
        "timeout_timer",
        "update_timer",
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


def router_ripng(data, fos, check_mode=False):
    state = data.get("state", None)

    router_ripng_data = data["router_ripng"]

    filtered_data = filter_router_ripng_data(router_ripng_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("router", "ripng", filtered_data)
        current_data = fos.get("router", "ripng", mkey=mkey)
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
        "ripng",
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
    fos.do_member_operation("router", "ripng")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["router_ripng"]:
        resp = router_ripng(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_ripng"))
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
        "default_metric": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "default-metric",
            "help": "Default metric of redistribute routes (Except connected).",
            "category": "unitary",
        },
        "timeout_timer": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "timeout-timer",
            "help": "Routing information timeout timer.",
            "category": "unitary",
        },
        "aggregate_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Aggregate-address entry id.",
                    "category": "unitary",
                },
                "prefix6": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "prefix6",
                    "help": "Aggregate-address prefix.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "aggregate-address",
            "help": "Set aggregate RIPng route announcement.",
            "mkey": "id",
            "category": "table",
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
                "access_list6": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "access-list6",
                    "help": "Ipv6 access list name.",
                    "category": "unitary",
                },
                "offset": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "offset",
                    "help": "Metric offset.",
                    "category": "unitary",
                },
                "interface": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "interface",
                    "help": "Interface name.",
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
            "help": "Offset list to modify RIPng metric.",
            "mkey": "id",
            "category": "table",
        },
        "bfd": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "bfd",
            "help": "Bidirectional Forwarding Detection (BFD).",
            "category": "unitary",
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
                    "help": "Flags",
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
        "interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "passive": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "passive",
                    "help": "Suppress routing updates on an interface.",
                    "category": "unitary",
                },
                "split_horizon_status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "split-horizon-status",
                    "help": "Enable/disable split horizon.",
                    "category": "unitary",
                },
                "split_horizon": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "poisoned"}, {"value": "regular"}],
                    "name": "split-horizon",
                    "help": "Split horizon type.",
                    "category": "unitary",
                },
                "flags": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "flags",
                    "help": "Flags.",
                    "category": "unitary",
                },
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Interface name.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "interface",
            "help": "RIPng interface configuration.",
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
    },
    "name": "ripng",
    "help": "router ripng configuration",
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
        "router_ripng": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_ripng"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_ripng"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_ripng"
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
