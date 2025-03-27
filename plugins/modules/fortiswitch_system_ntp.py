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
module: fortiswitch_system_ntp
short_description: Ntp system info configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and ntp category.
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

    system_ntp:
        description:
            - Ntp system info configuration.
        default: null
        type: dict
        suboptions:
            allow_unsync_source:
                description:
                    - Enable/disable allowance of unsynchronized NTP server source.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            authentication:
                description:
                    - Enable/disable authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            key:
                description:
                    - Key for authentication.
                type: str
            key_id:
                description:
                    - Key ID for authentication.
                type: int
            key_type:
                description:
                    - Key type for authentication (MD5, SHA1).
                type: str
                choices:
                    - 'MD5'
                    - 'SHA1'
            log_time_adjustments:
                description:
                    - Enable/disable logging of NTP time adjustments.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ntpserver:
                description:
                    - NTP server.
                type: list
                elements: dict
                suboptions:
                    authentication:
                        description:
                            - Enable/disable MD5(NTPv3)/SHA1(NTPv4) authentication.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - Time server ID.
                        type: int
                    key:
                        description:
                            - Key for MD5(NTPv3)/SHA1(NTPv4) authentication.
                        type: str
                    key_id:
                        description:
                            - Key ID for authentication.
                        type: int
                    ntpv3:
                        description:
                            - Enable to use NTPv3 instead of NTPv4.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    server:
                        description:
                            - IP address/hostname of NTP server.
                        type: str
            ntpsync:
                description:
                    - Enable/disable synchronization with NTP server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            server_mode:
                description:
                    - On Enabling, your FortiSwitch relays NTP requests to its configured NTP server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            source_ip:
                description:
                    - Source IP for communications to NTP server.
                type: str
            source_ip6:
                description:
                    - Source IPv6 address for communication to the NTP server.
                type: str
            syncinterval:
                description:
                    - NTP synchronization interval (1 - 1440) min.
                type: int
"""

EXAMPLES = """
- name: Ntp system info configuration.
  fortinet.fortiswitch.fortiswitch_system_ntp:
      system_ntp:
          allow_unsync_source: "enable"
          authentication: "enable"
          key: "<your_own_value>"
          key_id: "6"
          key_type: "MD5"
          log_time_adjustments: "enable"
          ntpserver:
              -
                  authentication: "enable"
                  id: "11"
                  key: "<your_own_value>"
                  key_id: "13"
                  ntpv3: "enable"
                  server: "192.168.100.40"
          ntpsync: "enable"
          server_mode: "enable"
          source_ip: "<your_own_value>"
          source_ip6: "<your_own_value>"
          syncinterval: "720"
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


def filter_system_ntp_data(json):
    option_list = [
        "allow_unsync_source",
        "authentication",
        "key",
        "key_id",
        "key_type",
        "log_time_adjustments",
        "ntpserver",
        "ntpsync",
        "server_mode",
        "source_ip",
        "source_ip6",
        "syncinterval",
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


def system_ntp(data, fos, check_mode=False):
    state = data.get("state", None)

    system_ntp_data = data["system_ntp"]

    filtered_data = filter_system_ntp_data(system_ntp_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system", "ntp", filtered_data)
        current_data = fos.get("system", "ntp", mkey=mkey)
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
        "ntp",
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
    fos.do_member_operation("system", "ntp")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["system_ntp"]:
        resp = system_ntp(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_ntp"))
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
        "key_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "MD5"}, {"value": "SHA1"}],
            "name": "key-type",
            "help": "Key type for authentication (MD5,SHA1).",
            "category": "unitary",
        },
        "log_time_adjustments": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "log-time-adjustments",
            "help": "Enable/disable logging of NTP time adjustments.",
            "category": "unitary",
        },
        "server_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "server-mode",
            "help": "On Enabling,your FortiSwitch relays NTP requests to its configured NTP server.",
            "category": "unitary",
        },
        "source_ip": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "source-ip",
            "help": "Source IP for communications to NTP server.",
            "category": "unitary",
        },
        "allow_unsync_source": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "allow-unsync-source",
            "help": "Enable/disable allowance of unsynchronized NTP server source.",
            "category": "unitary",
        },
        "authentication": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "authentication",
            "help": "Enable/disable authentication.",
            "category": "unitary",
        },
        "source_ip6": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "source-ip6",
            "help": "Source IPv6 address for communication to the NTP server.",
            "category": "unitary",
        },
        "key": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "key",
            "help": "Key for authentication.",
            "category": "unitary",
        },
        "ntpsync": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "ntpsync",
            "help": "Enable/disable synchronization with NTP server.",
            "category": "unitary",
        },
        "syncinterval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "syncinterval",
            "help": "NTP synchronization interval (1 - 1440) min.",
            "category": "unitary",
        },
        "ntpserver": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ntpv3": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "ntpv3",
                    "help": "Enable to use NTPv3 instead of NTPv4.",
                    "category": "unitary",
                },
                "server": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "server",
                    "help": "IP address/hostname of NTP server.",
                    "category": "unitary",
                },
                "authentication": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "authentication",
                    "help": "Enable/disable MD5(NTPv3)/SHA1(NTPv4) authentication.",
                    "category": "unitary",
                },
                "key": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "key",
                    "help": "Key for MD5(NTPv3)/SHA1(NTPv4) authentication.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Time server ID.",
                    "category": "unitary",
                },
                "key_id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "key-id",
                    "help": "Key ID for authentication.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "ntpserver",
            "help": "NTP server.",
            "mkey": "id",
            "category": "table",
        },
        "key_id": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "key-id",
            "help": "Key ID for authentication.",
            "category": "unitary",
        },
    },
    "name": "ntp",
    "help": "Ntp system info configuration.",
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
        "system_ntp": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_ntp"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_ntp"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_ntp"
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
