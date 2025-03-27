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
module: fortiswitch_switch_trunk
short_description: Link-aggregation in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch feature and trunk category.
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
    switch_trunk:
        description:
            - Link-aggregation.
        default: null
        type: dict
        suboptions:
            aggregator_mode:
                description:
                    - LACP Member Select Mode.
                type: str
                choices:
                    - 'bandwidth'
                    - 'count'
            auto_isl:
                description:
                    - Trunk with auto-isl.
                type: int
            bundle:
                description:
                    - Enable bundle.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            description:
                description:
                    - Description.
                type: str
            fallback_port:
                description:
                    - LACP fallback port.
                type: str
            fortilink:
                description:
                    - FortiLink trunk.
                type: int
            hb_dst_ip:
                description:
                    - Destination IP address of heartbeat packet.
                type: str
            hb_dst_udp_port:
                description:
                    - Destination UDP port of heartbeat packet.
                type: int
            hb_in_vlan:
                description:
                    - Receive VLAN ID in heartbeat packet.
                type: int
            hb_out_vlan:
                description:
                    - Transmit VLAN ID in heartbeat packet.
                type: int
            hb_src_ip:
                description:
                    - Source IP address of heartbeat packet.
                type: str
            hb_src_udp_port:
                description:
                    - Source UDP port of heartbeat packet.
                type: int
            hb_verify:
                description:
                    - Enable/disable heartbeat packet strict validation.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            isl_fortilink:
                description:
                    - ISL fortiLink trunk.
                type: int
            lacp_speed:
                description:
                    - LACP speed.
                type: str
                choices:
                    - 'slow'
                    - 'fast'
            max_bundle:
                description:
                    - Maximum size of bundle.
                type: int
            max_miss_heartbeats:
                description:
                    - Maximum tolerant missed heartbeats.
                type: int
            mclag:
                description:
                    - Multi Chassis LAG.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mclag_icl:
                description:
                    - MCLAG inter-chassis-link.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mclag_mac_address:
                description:
                    - MCLAG MAC address.
                type: str
            member_withdrawal_behavior:
                description:
                    - Port behaviors after it withdraws because of loss of control packets.
                type: str
                choices:
                    - 'forward'
                    - 'block'
            members:
                description:
                    - Aggregated interfaces.
                type: list
                elements: dict
                suboptions:
                    member_name:
                        description:
                            - Interface name.
                        type: str
            min_bundle:
                description:
                    - Minimum size of bundle.
                type: int
            mode:
                description:
                    - Link Aggreation mode.
                type: str
                choices:
                    - 'static'
                    - 'lacp-passive'
                    - 'lacp-active'
                    - 'fortinet-trunk'
            name:
                description:
                    - Trunk name.
                required: true
                type: str
            port_extension:
                description:
                    - Port extension enable.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            port_extension_trigger:
                description:
                    - Number of failed port to trigger the whole trunk down.
                type: int
            port_selection_criteria:
                description:
                    - Algorithm for aggregate port selection.
                type: str
                choices:
                    - 'src-mac'
                    - 'dst-mac'
                    - 'src-dst-mac'
                    - 'src-ip'
                    - 'dst-ip'
                    - 'src-dst-ip'
            restricted:
                description:
                    - Restricted ISL ICL trunk.
                type: int
            static_isl:
                description:
                    - Static ISL.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            static_isl_auto_vlan:
                description:
                    - User ISL auto VLAN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trunk_id:
                description:
                    - Internal id.
                type: int
"""

EXAMPLES = """
- name: Link-aggregation.
  fortinet.fortiswitch.fortiswitch_switch_trunk:
      state: "present"
      switch_trunk:
          aggregator_mode: "bandwidth"
          auto_isl: "4"
          bundle: "enable"
          description: "<your_own_value>"
          fallback_port: "<your_own_value>"
          fortilink: "8"
          hb_dst_ip: "<your_own_value>"
          hb_dst_udp_port: "10"
          hb_in_vlan: "11"
          hb_out_vlan: "12"
          hb_src_ip: "<your_own_value>"
          hb_src_udp_port: "14"
          hb_verify: "enable"
          isl_fortilink: "16"
          lacp_speed: "slow"
          max_bundle: "18"
          max_miss_heartbeats: "19"
          mclag: "enable"
          mclag_icl: "enable"
          mclag_mac_address: "<your_own_value>"
          member_withdrawal_behavior: "forward"
          members:
              -
                  member_name: "<your_own_value> (source switch.physical-port.name)"
          min_bundle: "26"
          mode: "static"
          name: "default_name_28"
          port_extension: "enable"
          port_extension_trigger: "30"
          port_selection_criteria: "src-mac"
          restricted: "0"
          static_isl: "enable"
          static_isl_auto_vlan: "enable"
          trunk_id: "35"
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


def filter_switch_trunk_data(json):
    option_list = [
        "aggregator_mode",
        "auto_isl",
        "bundle",
        "description",
        "fallback_port",
        "fortilink",
        "hb_dst_ip",
        "hb_dst_udp_port",
        "hb_in_vlan",
        "hb_out_vlan",
        "hb_src_ip",
        "hb_src_udp_port",
        "hb_verify",
        "isl_fortilink",
        "lacp_speed",
        "max_bundle",
        "max_miss_heartbeats",
        "mclag",
        "mclag_icl",
        "mclag_mac_address",
        "member_withdrawal_behavior",
        "members",
        "min_bundle",
        "mode",
        "name",
        "port_extension",
        "port_extension_trigger",
        "port_selection_criteria",
        "restricted",
        "static_isl",
        "static_isl_auto_vlan",
        "trunk_id",
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


def switch_trunk(data, fos, check_mode=False):
    state = data.get("state", None)

    switch_trunk_data = data["switch_trunk"]

    filtered_data = filter_switch_trunk_data(switch_trunk_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("switch", "trunk", filtered_data)
        current_data = fos.get("switch", "trunk", mkey=mkey)
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
            "switch",
            "trunk",
            data=filtered_data,
        )

    elif state == "absent":
        return fos.delete("switch", "trunk", mkey=filtered_data["name"])
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


def fortiswitch_switch(data, fos, check_mode):
    fos.do_member_operation("switch", "trunk")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["switch_trunk"]:
        resp = switch_trunk(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("switch_trunk"))
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
        "hb_src_udp_port": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "hb-src-udp-port",
            "help": "Source UDP port of heartbeat packet.",
            "category": "unitary",
        },
        "hb_verify": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "hb-verify",
            "help": "Enable/disable heartbeat packet strict validation.",
            "category": "unitary",
        },
        "hb_src_ip": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "hb-src-ip",
            "help": "Source IP address of heartbeat packet.",
            "category": "unitary",
        },
        "min_bundle": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "min-bundle",
            "help": "Minimum size of bundle.",
            "category": "unitary",
        },
        "hb_dst_udp_port": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "hb-dst-udp-port",
            "help": "Destination UDP port of heartbeat packet.",
            "category": "unitary",
        },
        "member_withdrawal_behavior": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "forward"}, {"value": "block"}],
            "name": "member-withdrawal-behavior",
            "help": "Port behaviors after it withdraws because of loss of control packets.",
            "category": "unitary",
        },
        "mclag_mac_address": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "mclag-mac-address",
            "help": "MCLAG MAC address.",
            "category": "unitary",
        },
        "isl_fortilink": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "isl-fortilink",
            "help": "ISL fortiLink trunk.",
            "category": "unitary",
        },
        "max_miss_heartbeats": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "max-miss-heartbeats",
            "help": "Maximum tolerant missed heartbeats.",
            "category": "unitary",
        },
        "aggregator_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "bandwidth"}, {"value": "count"}],
            "name": "aggregator-mode",
            "help": "LACP Member Select Mode.",
            "category": "unitary",
        },
        "port_selection_criteria": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "src-mac"},
                {"value": "dst-mac"},
                {"value": "src-dst-mac"},
                {"value": "src-ip"},
                {"value": "dst-ip"},
                {"value": "src-dst-ip"},
            ],
            "name": "port-selection-criteria",
            "help": "Algorithm for aggregate port selection.",
            "category": "unitary",
        },
        "lacp_speed": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "slow"}, {"value": "fast"}],
            "name": "lacp-speed",
            "help": "LACP speed.",
            "category": "unitary",
        },
        "mclag": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "mclag",
            "help": "Multi Chassis LAG.",
            "category": "unitary",
        },
        "trunk_id": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "trunk-id",
            "help": "Internal id.",
            "category": "unitary",
        },
        "description": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "description",
            "help": "Description.",
            "category": "unitary",
        },
        "static_isl_auto_vlan": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "static-isl-auto-vlan",
            "help": "User ISL auto VLAN.",
            "category": "unitary",
        },
        "bundle": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "bundle",
            "help": "Enable bundle.",
            "category": "unitary",
        },
        "max_bundle": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "max-bundle",
            "help": "Maximum size of bundle.",
            "category": "unitary",
        },
        "mclag_icl": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "mclag-icl",
            "help": "MCLAG inter-chassis-link.",
            "category": "unitary",
        },
        "hb_in_vlan": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "hb-in-vlan",
            "help": "Receive VLAN ID in heartbeat packet.",
            "category": "unitary",
        },
        "members": {
            "type": "list",
            "elements": "dict",
            "children": {
                "member_name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "member-name",
                    "help": "Interface name.",
                    "category": "unitary",
                }
            },
            "v_range": [["v7.0.0", ""]],
            "name": "members",
            "help": "Aggregated interfaces.",
            "mkey": "member-name",
            "category": "table",
        },
        "hb_dst_ip": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "hb-dst-ip",
            "help": "Destination IP address of heartbeat packet.",
            "category": "unitary",
        },
        "hb_out_vlan": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "hb-out-vlan",
            "help": "Transmit VLAN ID in heartbeat packet.",
            "category": "unitary",
        },
        "fortilink": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "fortilink",
            "help": "FortiLink trunk.",
            "category": "unitary",
        },
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "Trunk name.",
            "category": "unitary",
        },
        "auto_isl": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "auto-isl",
            "help": "Trunk with auto-isl.",
            "category": "unitary",
        },
        "port_extension": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "port-extension",
            "help": "Port extension enable.",
            "category": "unitary",
        },
        "mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "static"},
                {"value": "lacp-passive"},
                {"value": "lacp-active"},
                {"value": "fortinet-trunk"},
            ],
            "name": "mode",
            "help": "Link Aggreation mode.",
            "category": "unitary",
        },
        "static_isl": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "static-isl",
            "help": "Static ISL.",
            "category": "unitary",
        },
        "port_extension_trigger": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "port-extension-trigger",
            "help": "Number of failed port to trigger the whole trunk down.",
            "category": "unitary",
        },
        "fallback_port": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "name": "fallback-port",
            "help": "LACP fallback port.",
            "category": "unitary",
        },
        "restricted": {
            "v_range": [["v7.4.1", ""]],
            "type": "integer",
            "name": "restricted",
            "help": "Restricted ISL ICL trunk.",
            "category": "unitary",
        },
    },
    "v_range": [["v7.0.0", ""]],
    "name": "trunk",
    "help": "Link-aggregation.",
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
        "switch_trunk": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_trunk"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_trunk"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "switch_trunk"
        )
        is_error, has_changed, result, diff = fortiswitch_switch(
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
