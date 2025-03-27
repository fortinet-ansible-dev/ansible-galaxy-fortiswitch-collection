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
module: fortiswitch_system_snmp_user
short_description: SNMP user configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system_snmp feature and user category.
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
    system_snmp_user:
        description:
            - SNMP user configuration.
        default: null
        type: dict
        suboptions:
            auth_proto:
                description:
                    - Authentication protocol.
                type: str
                choices:
                    - 'md5'
                    - 'sha1'
                    - 'sha224'
                    - 'sha256'
                    - 'sha384'
                    - 'sha512'
            auth_pwd:
                description:
                    - Password for authentication protocol.
                type: str
            events:
                description:
                    - SNMP notifications (traps) to send.
                type: str
                choices:
                    - 'cpu-high'
                    - 'mem-low'
                    - 'log-full'
                    - 'intf-ip'
                    - 'ent-conf-change'
                    - 'llv'
                    - 'l2mac'
                    - 'sensor-fault'
                    - 'sensor-alarm'
                    - 'fan-detect'
                    - 'psu-status'
                    - 'ip-conflict'
                    - 'tkmem-hb-oo-sync'
                    - 'fsTrapStitch1'
                    - 'fsTrapStitch2'
                    - 'fsTrapStitch3'
                    - 'fsTrapStitch4'
                    - 'fsTrapStitch5'
                    - 'storm-control'
            name:
                description:
                    - SNMP user name.
                required: true
                type: str
            notify_hosts:
                description:
                    - Send notifications (traps) to these hosts.
                type: str
            priv_proto:
                description:
                    - Privacy (encryption) protocol.
                type: str
                choices:
                    - 'aes128'
                    - 'aes192'
                    - 'aes192c'
                    - 'aes256'
                    - 'aes256c'
                    - 'des'
            priv_pwd:
                description:
                    - Password for privacy (encryption) protocol.
                type: str
            queries:
                description:
                    - Enable/disable queries for this user.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            query_port:
                description:
                    - SNMPv3 query port.
                type: int
            security_level:
                description:
                    - Security level for message authentication and encryption.
                type: str
                choices:
                    - 'no-auth-no-priv'
                    - 'auth-no-priv'
                    - 'auth-priv'
"""

EXAMPLES = """
- name: SNMP user configuration.
  fortinet.fortiswitch.fortiswitch_system_snmp_user:
      state: "present"
      system_snmp_user:
          auth_proto: "md5"
          auth_pwd: "<your_own_value>"
          events: "cpu-high"
          name: "default_name_6"
          notify_hosts: "<your_own_value>"
          priv_proto: "aes128"
          priv_pwd: "<your_own_value>"
          queries: "enable"
          query_port: "11"
          security_level: "no-auth-no-priv"
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


def filter_system_snmp_user_data(json):
    option_list = [
        "auth_proto",
        "auth_pwd",
        "events",
        "name",
        "notify_hosts",
        "priv_proto",
        "priv_pwd",
        "queries",
        "query_port",
        "security_level",
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


def system_snmp_user(data, fos, check_mode=False):
    state = data.get("state", None)

    system_snmp_user_data = data["system_snmp_user"]

    filtered_data = filter_system_snmp_user_data(system_snmp_user_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system.snmp", "user", filtered_data)
        current_data = fos.get("system.snmp", "user", mkey=mkey)
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
            "system.snmp",
            "user",
            data=filtered_data,
        )

    elif state == "absent":
        return fos.delete("system.snmp", "user", mkey=filtered_data["name"])
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


def fortiswitch_system_snmp(data, fos, check_mode):
    fos.do_member_operation("system.snmp", "user")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["system_snmp_user"]:
        resp = system_snmp_user(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_snmp_user"))
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
        "notify_hosts": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "notify-hosts",
            "help": "Send notifications (traps) to these hosts.",
            "category": "unitary",
        },
        "priv_proto": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "aes128"},
                {"value": "aes192"},
                {"value": "aes192c"},
                {"value": "aes256"},
                {"value": "aes256c"},
                {"value": "des"},
            ],
            "name": "priv-proto",
            "help": "Privacy (encryption) protocol.",
            "category": "unitary",
        },
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "SNMP user name.",
            "category": "unitary",
        },
        "query_port": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "query-port",
            "help": "SNMPv3 query port.",
            "category": "unitary",
        },
        "auth_pwd": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "auth-pwd",
            "help": "Password for authentication protocol.",
            "category": "unitary",
        },
        "priv_pwd": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "priv-pwd",
            "help": "Password for privacy (encryption) protocol.",
            "category": "unitary",
        },
        "security_level": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "no-auth-no-priv"},
                {"value": "auth-no-priv"},
                {"value": "auth-priv"},
            ],
            "name": "security-level",
            "help": "Security level for message authentication and encryption.",
            "category": "unitary",
        },
        "auth_proto": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "md5"},
                {"value": "sha1"},
                {"value": "sha224"},
                {"value": "sha256"},
                {"value": "sha384"},
                {"value": "sha512"},
            ],
            "name": "auth-proto",
            "help": "Authentication protocol.",
            "category": "unitary",
        },
        "queries": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "queries",
            "help": "Enable/disable queries for this user.",
            "category": "unitary",
        },
        "events": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "cpu-high"},
                {"value": "mem-low"},
                {"value": "log-full"},
                {"value": "intf-ip"},
                {"value": "ent-conf-change"},
                {"value": "llv", "v_range": [["v7.0.2", ""]]},
                {"value": "l2mac", "v_range": [["v7.2.1", ""]]},
                {"value": "sensor-fault", "v_range": [["v7.2.1", ""]]},
                {"value": "sensor-alarm", "v_range": [["v7.2.1", ""]]},
                {"value": "fan-detect", "v_range": [["v7.2.1", ""]]},
                {"value": "psu-status", "v_range": [["v7.2.1", ""]]},
                {"value": "ip-conflict", "v_range": [["v7.2.1", ""]]},
                {"value": "tkmem-hb-oo-sync", "v_range": [["v7.2.1", ""]]},
                {"value": "fsTrapStitch1", "v_range": []},
                {"value": "fsTrapStitch2", "v_range": []},
                {"value": "fsTrapStitch3", "v_range": []},
                {"value": "fsTrapStitch4", "v_range": []},
                {"value": "fsTrapStitch5", "v_range": []},
                {"value": "storm-control", "v_range": []},
            ],
            "name": "events",
            "help": "SNMP notifications (traps) to send.",
            "category": "unitary",
        },
    },
    "v_range": [["v7.0.0", ""]],
    "name": "user",
    "help": "SNMP user configuration.",
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
        "system_snmp_user": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_snmp_user"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_snmp_user"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_snmp_user"
        )
        is_error, has_changed, result, diff = fortiswitch_system_snmp(
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
