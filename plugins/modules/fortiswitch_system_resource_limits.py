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
module: fortiswitch_system_resource_limits
short_description: Resource limits configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and resource_limits category.
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

    system_resource_limits:
        description:
            - Resource limits configuration.
        default: null
        type: dict
        suboptions:
            custom_service:
                description:
                    - Maximum number of firewall custom services.
                type: int
            dialup_tunnel:
                description:
                    - Maximum number of dial-up tunnels.
                type: int
            firewall_address:
                description:
                    - Maximum number of firewall addresses.
                type: int
            firewall_addrgrp:
                description:
                    - Maximum number of firewall address groups.
                type: int
            firewall_policy:
                description:
                    - Maximum number of firewall policies.
                type: int
            ipsec_phase1:
                description:
                    - Maximum number of vpn ipsec phase1 tunnels.
                type: int
            ipsec_phase2:
                description:
                    - Maximum number of vpn ipsec phase2 tunnels.
                type: int
            log_disk_quota:
                description:
                    - Log disk quota in MB.
                type: int
            onetime_schedule:
                description:
                    - Maximum number of firewall one-time schedules.
                type: int
            proxy:
                description:
                    - Maximum number of concurrent explicit proxy users.
                type: int
            recurring_schedule:
                description:
                    - Maximum number of firewall recurring schedules.
                type: int
            service_group:
                description:
                    - Maximum number of firewall service groups.
                type: int
            session:
                description:
                    - Maximum number of sessions.
                type: int
            user:
                description:
                    - Maximum number of local users.
                type: int
            user_group:
                description:
                    - Maximum number of user groups.
                type: int
"""

EXAMPLES = """
- name: Resource limits configuration.
  fortinet.fortiswitch.fortiswitch_system_resource_limits:
      system_resource_limits:
          custom_service: "3"
          dialup_tunnel: "4"
          firewall_address: "5"
          firewall_addrgrp: "6"
          firewall_policy: "7"
          ipsec_phase1: "8"
          ipsec_phase2: "9"
          log_disk_quota: "10"
          onetime_schedule: "11"
          proxy: "12"
          recurring_schedule: "13"
          service_group: "14"
          session: "15"
          user: "16"
          user_group: "17"
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


def filter_system_resource_limits_data(json):
    option_list = [
        "custom_service",
        "dialup_tunnel",
        "firewall_address",
        "firewall_addrgrp",
        "firewall_policy",
        "ipsec_phase1",
        "ipsec_phase2",
        "log_disk_quota",
        "onetime_schedule",
        "proxy",
        "recurring_schedule",
        "service_group",
        "session",
        "user",
        "user_group",
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


def system_resource_limits(data, fos, check_mode=False):
    state = data.get("state", None)

    system_resource_limits_data = data["system_resource_limits"]

    filtered_data = filter_system_resource_limits_data(system_resource_limits_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system", "resource-limits", filtered_data)
        current_data = fos.get("system", "resource-limits", mkey=mkey)
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
        "resource-limits",
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
    fos.do_member_operation("system", "resource-limits")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["system_resource_limits"]:
        resp = system_resource_limits(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_resource_limits"))
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
        "log_disk_quota": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "log-disk-quota",
            "help": "Log disk quota in MB.",
            "category": "unitary",
        },
        "user_group": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "user-group",
            "help": "Maximum number of user groups.",
            "category": "unitary",
        },
        "onetime_schedule": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "onetime-schedule",
            "help": "Maximum number of firewall one-time schedules.",
            "category": "unitary",
        },
        "recurring_schedule": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "recurring-schedule",
            "help": "Maximum number of firewall recurring schedules.",
            "category": "unitary",
        },
        "firewall_policy": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "firewall-policy",
            "help": "Maximum number of firewall policies.",
            "category": "unitary",
        },
        "service_group": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "service-group",
            "help": "Maximum number of firewall service groups.",
            "category": "unitary",
        },
        "custom_service": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "custom-service",
            "help": "Maximum number of firewall custom services.",
            "category": "unitary",
        },
        "ipsec_phase1": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "ipsec-phase1",
            "help": "Maximum number of vpn ipsec phase1 tunnels.",
            "category": "unitary",
        },
        "ipsec_phase2": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "ipsec-phase2",
            "help": "Maximum number of vpn ipsec phase2 tunnels.",
            "category": "unitary",
        },
        "session": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "session",
            "help": "Maximum number of sessions.",
            "category": "unitary",
        },
        "firewall_addrgrp": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "firewall-addrgrp",
            "help": "Maximum number of firewall address groups.",
            "category": "unitary",
        },
        "firewall_address": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "firewall-address",
            "help": "Maximum number of firewall addresses.",
            "category": "unitary",
        },
        "proxy": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "proxy",
            "help": "Maximum number of concurrent explicit proxy users.",
            "category": "unitary",
        },
        "dialup_tunnel": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "dialup-tunnel",
            "help": "Maximum number of dial-up tunnels.",
            "category": "unitary",
        },
        "user": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "user",
            "help": "Maximum number of local users.",
            "category": "unitary",
        },
    },
    "name": "resource-limits",
    "help": "Resource limits configuration.",
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
        "system_resource_limits": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_resource_limits"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_resource_limits"]["options"][attribute_name][
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
            fos, versioned_schema, "system_resource_limits"
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
