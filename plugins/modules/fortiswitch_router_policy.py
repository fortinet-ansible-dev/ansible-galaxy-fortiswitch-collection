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
module: fortiswitch_router_policy
short_description: Policy routing configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and policy category.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    router_policy:
        description:
            - Policy routing configuration.
        default: null
        type: dict
        suboptions:
            comments:
                description:
                    - Description/comments.
                type: str
            dst:
                description:
                    - Destination ip and mask.
                type: str
            end_port:
                description:
                    - End port number.
                type: int
            gateway:
                description:
                    - IP address of gateway.
                type: str
            input_device:
                description:
                    - Incoming interface name.
                type: str
            interface:
                description:
                    - Interface configuration.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name
                        type: str
                    pbr_map_name:
                        description:
                            - PBR policy map name.
                        type: str
            nexthop_group:
                description:
                    - Nexthop group (ECMP) configuration.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Name.
                        type: str
                    nexthop:
                        description:
                            - Nexthop configuration.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Id (1-64).
                                type: int
                            nexthop_ip:
                                description:
                                    - IP address of nexthop.
                                type: str
                            nexthop_vrf_name:
                                description:
                                    - VRF name.
                                type: str
            output_device:
                description:
                    - Outgoing interface name.
                type: str
            pbr_map:
                description:
                    - PBR map configuration.
                type: list
                elements: dict
                suboptions:
                    comments:
                        description:
                            - Description/comments.
                        type: str
                    name:
                        description:
                            - Name.
                        type: str
                    rule:
                        description:
                            - Rule.
                        type: list
                        elements: dict
                        suboptions:
                            dst:
                                description:
                                    - Destination ip and mask.
                                type: str
                            nexthop_group_name:
                                description:
                                    - Nexthop group name. Used for ECMP.
                                type: str
                            nexthop_ip:
                                description:
                                    - IP address of nexthop.
                                type: str
                            nexthop_vrf_name:
                                description:
                                    - Nexthop vrf name.
                                type: str
                            seq_num:
                                description:
                                    - Rule seq-num (1-10000).
                                type: int
                            src:
                                description:
                                    - Source ip and mask.
                                type: str
            protocol:
                description:
                    - Protocol number.
                type: int
            seq_num:
                description:
                    - Sequence number.
                type: int
            src:
                description:
                    - Source ip and mask.
                type: str
            start_port:
                description:
                    - Start port number.
                type: int
            tos:
                description:
                    - Terms of service bit pattern.
                type: str
            tos_mask:
                description:
                    - Terms of service evaluated bits.
                type: str
"""

EXAMPLES = """
- name: Policy routing configuration.
  fortinet.fortiswitch.fortiswitch_router_policy:
      state: "present"
      router_policy:
          comments: "<your_own_value>"
          dst: "<your_own_value>"
          end_port: "32767"
          gateway: "<your_own_value>"
          input_device: "<your_own_value> (source system.interface.name)"
          interface:
              -
                  name: "default_name_9 (source system.interface.name)"
                  pbr_map_name: "<your_own_value>"
          nexthop_group:
              -
                  name: "default_name_12"
                  nexthop:
                      -
                          id: "14"
                          nexthop_ip: "<your_own_value>"
                          nexthop_vrf_name: "<your_own_value> (source router.vrf.name)"
          output_device: "<your_own_value> (source system.interface.name)"
          pbr_map:
              -
                  comments: "<your_own_value>"
                  name: "default_name_20"
                  rule:
                      -
                          dst: "<your_own_value>"
                          nexthop_group_name: "<your_own_value>"
                          nexthop_ip: "<your_own_value>"
                          nexthop_vrf_name: "<your_own_value> (source router.vrf.name)"
                          seq_num: "<you_own_value>"
                          src: "<your_own_value>"
          protocol: "127"
          seq_num: "<you_own_value>"
          src: "<your_own_value>"
          start_port: "32767"
          tos: "<your_own_value>"
          tos_mask: "<your_own_value>"
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


def filter_router_policy_data(json):
    option_list = [
        "comments",
        "dst",
        "end_port",
        "gateway",
        "input_device",
        "interface",
        "nexthop_group",
        "output_device",
        "pbr_map",
        "protocol",
        "seq_num",
        "src",
        "start_port",
        "tos",
        "tos_mask",
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


def router_policy(data, fos, check_mode=False):
    state = data.get("state", None)

    router_policy_data = data["router_policy"]

    filtered_data = filter_router_policy_data(router_policy_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("router", "policy", filtered_data)
        current_data = fos.get("router", "policy", mkey=mkey)
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

    if state == "present" or state is True:
        return fos.set(
            "router",
            "policy",
            data=filtered_data,
        )

    elif state == "absent":
        return fos.delete("router", "policy", mkey=filtered_data["seq-num"])
    else:
        fos._module.fail_json(msg="state must be present or absent!")


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
    fos.do_member_operation("router", "policy")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["router_policy"]:
        resp = router_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_policy"))
    if check_mode:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp) and current_cmdb_index != resp["cmdb-index"],
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "src": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "string",
            "name": "src",
            "help": "Source ip and mask.",
            "category": "unitary",
        },
        "output_device": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "string",
            "name": "output-device",
            "help": "Outgoing interface name.",
            "category": "unitary",
        },
        "protocol": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "integer",
            "name": "protocol",
            "help": "Protocol number.",
            "category": "unitary",
        },
        "end_port": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "integer",
            "name": "end-port",
            "help": "End port number.",
            "category": "unitary",
        },
        "dst": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "string",
            "name": "dst",
            "help": "Destination ip and mask.",
            "category": "unitary",
        },
        "seq_num": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "integer",
            "name": "seq-num",
            "help": "Sequence number.",
            "category": "unitary",
        },
        "tos_mask": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "string",
            "name": "tos-mask",
            "help": "Terms of service evaluated bits.",
            "category": "unitary",
        },
        "input_device": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "string",
            "name": "input-device",
            "help": "Incoming interface name.",
            "category": "unitary",
        },
        "tos": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "string",
            "name": "tos",
            "help": "Terms of service bit pattern.",
            "category": "unitary",
        },
        "gateway": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "string",
            "name": "gateway",
            "help": "IP address of gateway.",
            "category": "unitary",
        },
        "start_port": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "integer",
            "name": "start-port",
            "help": "Start port number.",
            "category": "unitary",
        },
        "interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Interface name",
                    "category": "unitary",
                },
                "pbr_map_name": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "name": "pbr-map-name",
                    "help": "PBR policy map name.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.1", ""]],
            "name": "interface",
            "help": "Interface configuration.",
            "mkey": "name",
            "category": "table",
        },
        "nexthop_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "nexthop": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "nexthop_vrf_name": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "name": "nexthop-vrf-name",
                            "help": "VRF name.",
                            "category": "unitary",
                        },
                        "nexthop_ip": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "name": "nexthop-ip",
                            "help": "IP address of nexthop.",
                            "category": "unitary",
                        },
                        "id": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "integer",
                            "name": "id",
                            "help": "Id (1-64).",
                            "category": "unitary",
                        },
                    },
                    "v_range": [["v7.0.1", ""]],
                    "name": "nexthop",
                    "help": "Nexthop configuration.",
                    "mkey": "id",
                    "category": "table",
                },
                "name": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Name.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.1", ""]],
            "name": "nexthop-group",
            "help": "Nexthop group (ECMP) configuration.",
            "mkey": "name",
            "category": "table",
        },
        "pbr_map": {
            "type": "list",
            "elements": "dict",
            "children": {
                "rule": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "src": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "name": "src",
                            "help": "Source ip and mask.",
                            "category": "unitary",
                        },
                        "nexthop_vrf_name": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "name": "nexthop-vrf-name",
                            "help": "Nexthop vrf name.",
                            "category": "unitary",
                        },
                        "nexthop_group_name": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "name": "nexthop-group-name",
                            "help": "Nexthop group name. Used for ECMP.",
                            "category": "unitary",
                        },
                        "dst": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "name": "dst",
                            "help": "Destination ip and mask.",
                            "category": "unitary",
                        },
                        "nexthop_ip": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "name": "nexthop-ip",
                            "help": "IP address of nexthop.",
                            "category": "unitary",
                        },
                        "seq_num": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "integer",
                            "name": "seq-num",
                            "help": "Rule seq-num (1-10000).",
                            "category": "unitary",
                        },
                    },
                    "v_range": [["v7.0.1", ""]],
                    "name": "rule",
                    "help": "Rule.",
                    "mkey": "seq-num",
                    "category": "table",
                },
                "name": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Name.",
                    "category": "unitary",
                },
                "comments": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "name": "comments",
                    "help": "Description/comments.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.1", ""]],
            "name": "pbr-map",
            "help": "PBR map configuration.",
            "mkey": "name",
            "category": "table",
        },
        "comments": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "name": "comments",
            "help": "Description/comments.",
            "category": "unitary",
        },
    },
    "v_range": [["v7.0.0", ""]],
    "name": "policy",
    "help": "Policy routing configuration.",
    "mkey": "seq-num",
    "category": "table",
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
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "router_policy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_policy"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_policy"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_policy"
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
