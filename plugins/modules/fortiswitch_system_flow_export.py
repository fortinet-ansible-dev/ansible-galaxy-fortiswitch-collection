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
module: fortiswitch_system_flow_export
short_description: System Flow Export settings in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and flow_export category.
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

    system_flow_export:
        description:
            - System Flow Export settings.
        default: null
        type: dict
        suboptions:
            aggregates:
                description:
                    - Aggregates.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Aggregate id.
                        type: int
                    ip:
                        description:
                            - Aggregate"s IP and Mask.
                        type: str
            collectors:
                description:
                    - Collectors.
                type: list
                elements: dict
                suboptions:
                    ip:
                        description:
                            - IP address.
                        type: str
                    name:
                        description:
                            - Collector name.
                        type: str
                    port:
                        description:
                            - 'Port number (0-65535).'
                        type: int
                    transport:
                        description:
                            - Export transport (udp|tcp|sctp).
                        type: str
                        choices:
                            - 'udp'
                            - 'tcp'
                            - 'sctp'
            filter:
                description:
                    - Filter (BPF).
                type: str
            format:
                description:
                    - Export Format (netflow1|netflow5|netflow9|ipfix).
                type: str
                choices:
                    - 'netflow1'
                    - 'netflow5'
                    - 'netflow9'
                    - 'ipfix'
            identity:
                description:
                    - Set identity of switch (0x00000000-0xFFFFFFFF ).
                type: int
            level:
                description:
                    - Export Level (vlan|ip|port|protocol|mac).
                type: str
                choices:
                    - 'mac'
                    - 'ip'
                    - 'proto'
                    - 'port'
                    - 'vlan'
            max_export_pkt_size:
                description:
                    - Max Export Packet Size (512-9216).
                type: int
            template_export_period:
                description:
                    - Template export period in minutes (1-60).
                type: int
            timeout_general:
                description:
                    - Flow Session General Timeout (60-604800).
                type: int
            timeout_icmp:
                description:
                    - Flow Session ICMP Timeout (60-604800).
                type: int
            timeout_max:
                description:
                    - Flow Session MAX Timeout (60-604800).
                type: int
            timeout_tcp:
                description:
                    - Flow Session TCP Timeout (60-604800).
                type: int
            timeout_tcp_fin:
                description:
                    - Flow Session TCP Fin Timeout (60-604800).
                type: int
            timeout_tcp_rst:
                description:
                    - Flow Session TCP Reset Timeout (60-604800).
                type: int
            timeout_udp:
                description:
                    - Flow Session UDP Timeout (60-604800).
                type: int
"""

EXAMPLES = """
- name: System Flow Export settings.
  fortinet.fortiswitch.fortiswitch_system_flow_export:
      system_flow_export:
          aggregates:
              -
                  id: "4"
                  ip: "<your_own_value>"
          collectors:
              -
                  ip: "<your_own_value>"
                  name: "default_name_8"
                  port: "32767"
                  transport: "udp"
          filter: "<your_own_value>"
          format: "netflow1"
          identity: "13"
          level: "mac"
          max_export_pkt_size: "4608"
          template_export_period: "30"
          timeout_general: "302400"
          timeout_icmp: "302400"
          timeout_max: "302400"
          timeout_tcp: "302400"
          timeout_tcp_fin: "302400"
          timeout_tcp_rst: "302400"
          timeout_udp: "302400"
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


def filter_system_flow_export_data(json):
    option_list = [
        "aggregates",
        "collectors",
        "filter",
        "format",
        "identity",
        "level",
        "max_export_pkt_size",
        "template_export_period",
        "timeout_general",
        "timeout_icmp",
        "timeout_max",
        "timeout_tcp",
        "timeout_tcp_fin",
        "timeout_tcp_rst",
        "timeout_udp",
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


def system_flow_export(data, fos, check_mode=False):
    state = data.get("state", None)

    system_flow_export_data = data["system_flow_export"]

    filtered_data = filter_system_flow_export_data(system_flow_export_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system", "flow-export", filtered_data)
        current_data = fos.get("system", "flow-export", mkey=mkey)
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
        "system",
        "flow-export",
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


def fortiswitch_system(data, fos, check_mode):
    fos.do_member_operation("system", "flow-export")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["system_flow_export"]:
        resp = system_flow_export(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_flow_export"))
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
        "timeout_tcp": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "timeout-tcp",
            "help": "Flow Session TCP Timeout (60-604800,default=3600 seconds).",
            "category": "unitary",
        },
        "timeout_udp": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "timeout-udp",
            "help": "Flow Session UDP Timeout (60-604800,default=300 seconds).",
            "category": "unitary",
        },
        "collectors": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "ip",
                    "help": "IP address.",
                    "category": "unitary",
                },
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Collector name.",
                    "category": "unitary",
                },
                "transport": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "udp"}, {"value": "tcp"}, {"value": "sctp"}],
                    "name": "transport",
                    "help": "Export transport (udp|tcp|sctp).",
                    "category": "unitary",
                },
                "port": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "port",
                    "help": "Port number (0-65535,default=0 (netflow:2055,ipfix:4739).",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "collectors",
            "help": "Collectors.",
            "mkey": "name",
            "category": "table",
        },
        "level": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "mac"},
                {"value": "ip"},
                {"value": "proto"},
                {"value": "port"},
                {"value": "vlan"},
            ],
            "name": "level",
            "help": "Export Level (vlan|ip|port|protocol|mac).",
            "category": "unitary",
        },
        "timeout_tcp_rst": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "timeout-tcp-rst",
            "help": "Flow Session TCP Reset Timeout (60-604800,default=120 seconds).",
            "category": "unitary",
        },
        "aggregates": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "ip",
                    "help": "Aggregate's IP and Mask.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Aggregate id.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "aggregates",
            "help": "Aggregates.",
            "mkey": "id",
            "category": "table",
        },
        "format": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "netflow1"},
                {"value": "netflow5"},
                {"value": "netflow9"},
                {"value": "ipfix"},
            ],
            "name": "format",
            "help": "Export Format (netflow1|netflow5|netflow9|ipfix).",
            "category": "unitary",
        },
        "timeout_tcp_fin": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "timeout-tcp-fin",
            "help": "Flow Session TCP Fin Timeout (60-604800,default=300 seconds).",
            "category": "unitary",
        },
        "template_export_period": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "template-export-period",
            "help": "Template export period in minutes (1-60).",
            "category": "unitary",
        },
        "filter": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "filter",
            "help": "Filter (BPF).",
            "category": "unitary",
        },
        "timeout_icmp": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "timeout-icmp",
            "help": "Flow Session ICMP Timeout (60-604800,default=300 seconds).",
            "category": "unitary",
        },
        "max_export_pkt_size": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "max-export-pkt-size",
            "help": "Max Export Packet Size (512-9216,default=512 bytes).",
            "category": "unitary",
        },
        "timeout_general": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "timeout-general",
            "help": "Flow Session General Timeout (60-604800,default=3600 seconds).",
            "category": "unitary",
        },
        "identity": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "identity",
            "help": "Set identity of switch (0x00000000-0xFFFFFFFF default=0x00000000).",
            "category": "unitary",
        },
        "timeout_max": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "timeout-max",
            "help": "Flow Session MAX Timeout (60-604800,default=604800 seconds).",
            "category": "unitary",
        },
    },
    "name": "flow-export",
    "help": "System Flow Export settings.",
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
        "system_flow_export": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_flow_export"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_flow_export"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_flow_export"
        )
        is_error, has_changed, result, diff = fortiswitch_system(
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
