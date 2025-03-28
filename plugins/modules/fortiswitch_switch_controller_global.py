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
module: fortiswitch_switch_controller_global
short_description: Switch-controller global configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch_controller feature and global category.
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

    switch_controller_global:
        description:
            - Switch-controller global configuration.
        default: null
        type: dict
        suboptions:
            ac_data_port:
                description:
                    - Switch controller data port [1024, 49150].
                type: int
            ac_dhcp_option_code:
                description:
                    - DHCP option code for CAPUTP AC.
                type: int
            ac_discovery_mc_addr:
                description:
                    - Discovery multicast address
                type: str
            ac_discovery_type:
                description:
                    - AC discovery type.
                type: str
                choices:
                    - 'static'
                    - 'dhcp'
                    - 'broadcast'
                    - 'multicast'
                    - 'auto'
                    - 'disable'
            ac_list:
                description:
                    - AC list.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Id.
                        type: int
                    ipv4_address:
                        description:
                            - IP addr.
                        type: str
                    ipv6_address:
                        description:
                            - IPv6 address.
                        type: str
            ac_port:
                description:
                    - Switch controller ctl port [1024, 49150].
                type: int
            echo_interval:
                description:
                    - Interval before SWTP sends Echo Request after joining AC. [1, 600] default = 30s.
                type: int
            location:
                description:
                    - Location.
                type: str
            max_discoveries:
                description:
                    - The maximum # of Discovery Request messages every round.
                type: int
            max_retransmit:
                description:
                    - The maximum # of retransmissions for tunnel packet.
                type: int
            mgmt_mode:
                description:
                    - FortiLink management mode.
                type: str
                choices:
                    - 'capwap'
                    - 'https'
            name:
                description:
                    - Name.
                type: str
            tunnel_mode:
                description:
                    - Compatible/strict tunnel mode.
                type: str
                choices:
                    - 'compatible'
                    - 'strict'
"""

EXAMPLES = """
- name: Switch-controller global configuration.
  fortinet.fortiswitch.fortiswitch_switch_controller_global:
      switch_controller_global:
          ac_data_port: "24575"
          ac_dhcp_option_code: "4"
          ac_discovery_mc_addr: "<your_own_value>"
          ac_discovery_type: "static"
          ac_list:
              -
                  id: "8"
                  ipv4_address: "<your_own_value>"
                  ipv6_address: "<your_own_value>"
          ac_port: "24575"
          echo_interval: "300"
          location: "<your_own_value>"
          max_discoveries: "32"
          max_retransmit: "32"
          mgmt_mode: "capwap"
          name: "default_name_17"
          tunnel_mode: "compatible"
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


def filter_switch_controller_global_data(json):
    option_list = [
        "ac_data_port",
        "ac_dhcp_option_code",
        "ac_discovery_mc_addr",
        "ac_discovery_type",
        "ac_list",
        "ac_port",
        "echo_interval",
        "location",
        "max_discoveries",
        "max_retransmit",
        "mgmt_mode",
        "name",
        "tunnel_mode",
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


def switch_controller_global(data, fos, check_mode=False):
    state = data.get("state", None)

    switch_controller_global_data = data["switch_controller_global"]

    filtered_data = filter_switch_controller_global_data(switch_controller_global_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("switch-controller", "global", filtered_data)
        current_data = fos.get("switch-controller", "global", mkey=mkey)
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
        "switch-controller",
        "global",
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


def fortiswitch_switch_controller(data, fos, check_mode):
    fos.do_member_operation("switch-controller", "global")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["switch_controller_global"]:
        resp = switch_controller_global(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("switch_controller_global")
        )
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
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "Name.",
            "category": "unitary",
        },
        "ac_data_port": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "ac-data-port",
            "help": "Switch controller data port [1024,49150].",
            "category": "unitary",
        },
        "echo_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "echo-interval",
            "help": "Interval before SWTP sends Echo Request after joining AC. [1,600] default = 30s.",
            "category": "unitary",
        },
        "ac_dhcp_option_code": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "ac-dhcp-option-code",
            "help": "DHCP option code for CAPUTP AC.",
            "category": "unitary",
        },
        "max_discoveries": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "max-discoveries",
            "help": "The maximum # of Discovery Request messages every round.",
            "category": "unitary",
        },
        "ac_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ipv4_address": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "ipv4-address",
                    "help": "IP addr.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Id.",
                    "category": "unitary",
                },
                "ipv6_address": {
                    "v_range": [["v7.2.3", ""]],
                    "type": "string",
                    "name": "ipv6-address",
                    "help": "IPv6 address.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "ac-list",
            "help": "AC list.",
            "mkey": "id",
            "category": "table",
        },
        "location": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "location",
            "help": "Location.",
            "category": "unitary",
        },
        "ac_discovery_mc_addr": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ac-discovery-mc-addr",
            "help": "Discovery multicast address",
            "category": "unitary",
        },
        "ac_port": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "ac-port",
            "help": "Switch controller ctl port [1024,49150].",
            "category": "unitary",
        },
        "max_retransmit": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "max-retransmit",
            "help": "The maximum # of retransmissions for tunnel packet.",
            "category": "unitary",
        },
        "ac_discovery_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "static"},
                {"value": "dhcp"},
                {"value": "broadcast"},
                {"value": "multicast"},
                {"value": "auto", "v_range": [["v7.2.1", ""]]},
                {"value": "disable", "v_range": [["v7.2.3", ""]]},
            ],
            "name": "ac-discovery-type",
            "help": "AC discovery type.",
            "category": "unitary",
        },
        "tunnel_mode": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "compatible"}, {"value": "strict"}],
            "name": "tunnel-mode",
            "help": "Compatible/strict tunnel mode.",
            "category": "unitary",
        },
        "mgmt_mode": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "capwap"}, {"value": "https"}],
            "name": "mgmt-mode",
            "help": "FortiLink management mode.",
            "category": "unitary",
        },
    },
    "name": "global",
    "help": "Switch-controller global configuration.",
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
        "switch_controller_global": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_controller_global"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_controller_global"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "switch_controller_global"
        )
        is_error, has_changed, result, diff = fortiswitch_switch_controller(
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
