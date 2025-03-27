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
module: fortiswitch_system_link_monitor
short_description: Configure Link Health Monitor in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and link_monitor category.
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
    system_link_monitor:
        description:
            - Configure Link Health Monitor.
        default: null
        type: dict
        suboptions:
            addr_mode:
                description:
                    - Address mode (IPv4 or IPv6).
                type: str
                choices:
                    - 'ipv4'
                    - 'ipv6'
            failtime:
                description:
                    - Number of retry attempts before bringing server down.
                type: int
            gateway_ip:
                description:
                    - Gateway IP used to PING the server.
                type: str
            gateway_ip6:
                description:
                    - Gateway IPv6 address used to PING the server.
                type: str
            http_get:
                description:
                    - HTTP GET URL string.
                type: str
            http_match:
                description:
                    - Response value from detected server in http-get.
                type: str
            interval:
                description:
                    - Detection interval.
                type: int
            name:
                description:
                    - Link monitor name.
                required: true
                type: str
            packet_size:
                description:
                    - Packet size of a twamp test session,.
                type: int
            password:
                description:
                    - Twamp controller password in authentication mode.
                type: str
            port:
                description:
                    - Port number to poll.
                type: int
            protocol:
                description:
                    - Protocols used to detect the server.
                type: list
                elements: str
                choices:
                    - 'arp'
                    - 'ping'
                    - 'ping6'
            recoverytime:
                description:
                    - Number of retry attempts before bringing server up.
                type: int
            security_mode:
                description:
                    - Twamp controller security mode.
                type: str
                choices:
                    - 'none'
                    - 'authentication'
            server:
                description:
                    - Server address(es).
                type: list
                elements: dict
                suboptions:
                    address:
                        description:
                            - Server address.
                        type: str
            source_ip:
                description:
                    - Source IP used in packet to the server.
                type: str
            source_ip6:
                description:
                    - Source IPv6 address used in packet to the server.
                type: str
            srcintf:
                description:
                    - Interface where the monitor traffic is sent.
                type: str
            status:
                description:
                    - Enable/disable link monitor administrative status.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            timeout:
                description:
                    - Detect request timeout.
                type: int
            update_cascade_interface:
                description:
                    - Enable/disable update cascade interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            update_static_route:
                description:
                    - Enable/disable update static route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure Link Health Monitor.
  fortinet.fortiswitch.fortiswitch_system_link_monitor:
      state: "present"
      system_link_monitor:
          addr_mode: "ipv4"
          failtime: "5"
          gateway_ip: "<your_own_value>"
          gateway_ip6: "<your_own_value>"
          http_get: "<your_own_value>"
          http_match: "<your_own_value>"
          interval: "1800"
          name: "default_name_10"
          packet_size: "512"
          password: "<your_own_value>"
          port: "32767"
          protocol: "arp"
          recoverytime: "5"
          security_mode: "none"
          server:
              -
                  address: "<your_own_value>"
          source_ip: "<your_own_value>"
          source_ip6: "<your_own_value>"
          srcintf: "<your_own_value> (source system.interface.name)"
          status: "enable"
          timeout: "127"
          update_cascade_interface: "enable"
          update_static_route: "enable"
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


def filter_system_link_monitor_data(json):
    option_list = [
        "addr_mode",
        "failtime",
        "gateway_ip",
        "gateway_ip6",
        "http_get",
        "http_match",
        "interval",
        "name",
        "packet_size",
        "password",
        "port",
        "protocol",
        "recoverytime",
        "security_mode",
        "server",
        "source_ip",
        "source_ip6",
        "srcintf",
        "status",
        "timeout",
        "update_cascade_interface",
        "update_static_route",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or not data[path[index]]
        and not isinstance(data[path[index]], list)
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None

    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["protocol"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


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


def system_link_monitor(data, fos, check_mode=False):
    state = data.get("state", None)

    system_link_monitor_data = data["system_link_monitor"]

    filtered_data = filter_system_link_monitor_data(system_link_monitor_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system", "link-monitor", filtered_data)
        current_data = fos.get("system", "link-monitor", mkey=mkey)
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
            "system",
            "link-monitor",
            data=filtered_data,
        )

    elif state == "absent":
        return fos.delete("system", "link-monitor", mkey=filtered_data["name"])
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


def fortiswitch_system(data, fos, check_mode):
    fos.do_member_operation("system", "link-monitor")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["system_link_monitor"]:
        resp = system_link_monitor(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_link_monitor"))
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
        "update_cascade_interface": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "update-cascade-interface",
            "help": "Enable/disable update cascade interface.",
            "category": "unitary",
        },
        "status": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "status",
            "help": "Enable/disable link monitor administrative status.",
            "category": "unitary",
        },
        "timeout": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "timeout",
            "help": "Detect request timeout.",
            "category": "unitary",
        },
        "protocol": {
            "v_range": [["v7.0.0", ""]],
            "type": "list",
            "options": [{"value": "arp"}, {"value": "ping"}, {"value": "ping6"}],
            "name": "protocol",
            "help": "Protocols used to detect the server.",
            "category": "unitary",
            "elements": "str",
        },
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "Link monitor name.",
            "category": "unitary",
        },
        "http_match": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "http-match",
            "help": "Response value from detected server in http-get.",
            "category": "unitary",
        },
        "source_ip": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "source-ip",
            "help": "Source IP used in packet to the server.",
            "category": "unitary",
        },
        "interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "interval",
            "help": "Detection interval.",
            "category": "unitary",
        },
        "gateway_ip6": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "gateway-ip6",
            "help": "Gateway IPv6 address used to PING the server.",
            "category": "unitary",
        },
        "failtime": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "failtime",
            "help": "Number of retry attempts before bringing server down.",
            "category": "unitary",
        },
        "update_static_route": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "update-static-route",
            "help": "Enable/disable update static route.",
            "category": "unitary",
        },
        "addr_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "ipv4"}, {"value": "ipv6"}],
            "name": "addr-mode",
            "help": "Address mode (IPv4 or IPv6).",
            "category": "unitary",
        },
        "http_get": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "http-get",
            "help": "HTTP GET URL string.",
            "category": "unitary",
        },
        "source_ip6": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "source-ip6",
            "help": "Source IPv6 address used in packet to the server.",
            "category": "unitary",
        },
        "srcintf": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "srcintf",
            "help": "Interface where the monitor traffic is sent.",
            "category": "unitary",
        },
        "security_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "authentication"}],
            "name": "security-mode",
            "help": "Twamp controller security mode.",
            "category": "unitary",
        },
        "packet_size": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "packet-size",
            "help": "Packet size of a twamp test session,.",
            "category": "unitary",
        },
        "gateway_ip": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "gateway-ip",
            "help": "Gateway IP used to PING the server.",
            "category": "unitary",
        },
        "password": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "password",
            "help": "Twamp controller password in authentication mode.",
            "category": "unitary",
        },
        "port": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "port",
            "help": "Port number to poll.",
            "category": "unitary",
        },
        "recoverytime": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "recoverytime",
            "help": "Number of retry attempts before bringing server up.",
            "category": "unitary",
        },
        "server": {
            "type": "list",
            "elements": "dict",
            "children": {
                "address": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "name": "address",
                    "help": "Server address.",
                    "category": "unitary",
                }
            },
            "v_range": [["v7.4.2", ""]],
            "name": "server",
            "help": "Server address(es).",
            "mkey": "address",
            "category": "table",
        },
    },
    "v_range": [["v7.0.0", ""]],
    "name": "link-monitor",
    "help": "Configure Link Health Monitor.",
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
        "system_link_monitor": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_link_monitor"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_link_monitor"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_link_monitor"
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
