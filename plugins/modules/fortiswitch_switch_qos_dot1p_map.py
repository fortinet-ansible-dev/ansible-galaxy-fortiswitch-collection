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
module: fortiswitch_switch_qos_dot1p_map
short_description: QOS 802.1p configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch_qos feature and dot1p_map category.
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
    switch_qos_dot1p_map:
        description:
            - QOS 802.1p configuration.
        default: null
        type: dict
        suboptions:
            description:
                description:
                    - Description of the 802.1p name.
                type: str
            egress_pri_tagging:
                description:
                    - Enable/disable egress priority-tag frame.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - Dot1p map name.
                required: true
                type: str
            priority_0:
                description:
                    - COS queue mapped by priority number (PCP in 802.1q).
                type: str
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_1:
                description:
                    - COS queue mapped by priority number (PCP in 802.1q).
                type: str
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_2:
                description:
                    - COS queue mapped by priority number (PCP in 802.1q).
                type: str
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_3:
                description:
                    - COS queue mapped by priority number (PCP in 802.1q).
                type: str
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_4:
                description:
                    - COS queue mapped by priority number (PCP in 802.1q).
                type: str
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_5:
                description:
                    - COS queue mapped by priority number (PCP in 802.1q).
                type: str
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_6:
                description:
                    - COS queue mapped by priority number (PCP in 802.1q).
                type: str
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_7:
                description:
                    - COS queue mapped by priority number (PCP in 802.1q).
                type: str
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
"""

EXAMPLES = """
- name: QOS 802.1p configuration.
  fortinet.fortiswitch.fortiswitch_switch_qos_dot1p_map:
      state: "present"
      switch_qos_dot1p_map:
          description: "<your_own_value>"
          egress_pri_tagging: "disable"
          name: "default_name_5"
          priority_0: "queue-0"
          priority_1: "queue-0"
          priority_2: "queue-0"
          priority_3: "queue-0"
          priority_4: "queue-0"
          priority_5: "queue-0"
          priority_6: "queue-0"
          priority_7: "queue-0"
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


def filter_switch_qos_dot1p_map_data(json):
    option_list = [
        "description",
        "egress_pri_tagging",
        "name",
        "priority_0",
        "priority_1",
        "priority_2",
        "priority_3",
        "priority_4",
        "priority_5",
        "priority_6",
        "priority_7",
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


def switch_qos_dot1p_map(data, fos, check_mode=False):
    state = data.get("state", None)

    switch_qos_dot1p_map_data = data["switch_qos_dot1p_map"]

    filtered_data = filter_switch_qos_dot1p_map_data(switch_qos_dot1p_map_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("switch.qos", "dot1p-map", filtered_data)
        current_data = fos.get("switch.qos", "dot1p-map", mkey=mkey)
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
            "switch.qos",
            "dot1p-map",
            data=filtered_data,
        )

    elif state == "absent":
        return fos.delete("switch.qos", "dot1p-map", mkey=filtered_data["name"])
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


def fortiswitch_switch_qos(data, fos, check_mode):
    fos.do_member_operation("switch.qos", "dot1p-map")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["switch_qos_dot1p_map"]:
        resp = switch_qos_dot1p_map(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("switch_qos_dot1p_map"))
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
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "Dot1p map name.",
            "category": "unitary",
        },
        "priority_5": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "queue-0"},
                {"value": "queue-1"},
                {"value": "queue-2"},
                {"value": "queue-3"},
                {"value": "queue-4"},
                {"value": "queue-5"},
                {"value": "queue-6"},
                {"value": "queue-7"},
            ],
            "name": "priority-5",
            "help": "COS queue mapped by priority number (PCP in 802.1q).",
            "category": "unitary",
        },
        "priority_4": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "queue-0"},
                {"value": "queue-1"},
                {"value": "queue-2"},
                {"value": "queue-3"},
                {"value": "queue-4"},
                {"value": "queue-5"},
                {"value": "queue-6"},
                {"value": "queue-7"},
            ],
            "name": "priority-4",
            "help": "COS queue mapped by priority number (PCP in 802.1q).",
            "category": "unitary",
        },
        "priority_7": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "queue-0"},
                {"value": "queue-1"},
                {"value": "queue-2"},
                {"value": "queue-3"},
                {"value": "queue-4"},
                {"value": "queue-5"},
                {"value": "queue-6"},
                {"value": "queue-7"},
            ],
            "name": "priority-7",
            "help": "COS queue mapped by priority number (PCP in 802.1q).",
            "category": "unitary",
        },
        "priority_6": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "queue-0"},
                {"value": "queue-1"},
                {"value": "queue-2"},
                {"value": "queue-3"},
                {"value": "queue-4"},
                {"value": "queue-5"},
                {"value": "queue-6"},
                {"value": "queue-7"},
            ],
            "name": "priority-6",
            "help": "COS queue mapped by priority number (PCP in 802.1q).",
            "category": "unitary",
        },
        "priority_1": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "queue-0"},
                {"value": "queue-1"},
                {"value": "queue-2"},
                {"value": "queue-3"},
                {"value": "queue-4"},
                {"value": "queue-5"},
                {"value": "queue-6"},
                {"value": "queue-7"},
            ],
            "name": "priority-1",
            "help": "COS queue mapped by priority number (PCP in 802.1q).",
            "category": "unitary",
        },
        "priority_0": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "queue-0"},
                {"value": "queue-1"},
                {"value": "queue-2"},
                {"value": "queue-3"},
                {"value": "queue-4"},
                {"value": "queue-5"},
                {"value": "queue-6"},
                {"value": "queue-7"},
            ],
            "name": "priority-0",
            "help": "COS queue mapped by priority number (PCP in 802.1q).",
            "category": "unitary",
        },
        "priority_3": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "queue-0"},
                {"value": "queue-1"},
                {"value": "queue-2"},
                {"value": "queue-3"},
                {"value": "queue-4"},
                {"value": "queue-5"},
                {"value": "queue-6"},
                {"value": "queue-7"},
            ],
            "name": "priority-3",
            "help": "COS queue mapped by priority number (PCP in 802.1q).",
            "category": "unitary",
        },
        "priority_2": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "queue-0"},
                {"value": "queue-1"},
                {"value": "queue-2"},
                {"value": "queue-3"},
                {"value": "queue-4"},
                {"value": "queue-5"},
                {"value": "queue-6"},
                {"value": "queue-7"},
            ],
            "name": "priority-2",
            "help": "COS queue mapped by priority number (PCP in 802.1q).",
            "category": "unitary",
        },
        "egress_pri_tagging": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
            "name": "egress-pri-tagging",
            "help": "Enable/disable egress priority-tag frame.",
            "category": "unitary",
        },
        "description": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "description",
            "help": "Description of the 802.1p name.",
            "category": "unitary",
        },
    },
    "v_range": [["v7.0.0", ""]],
    "name": "dot1p-map",
    "help": "QOS 802.1p configuration.",
    "mkey": "name",
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
        "switch_qos_dot1p_map": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_qos_dot1p_map"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_qos_dot1p_map"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "switch_qos_dot1p_map"
        )
        is_error, has_changed, result, diff = fortiswitch_switch_qos(
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
