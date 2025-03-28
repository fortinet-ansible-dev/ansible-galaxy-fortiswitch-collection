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
module: fortiswitch_user_radius
short_description: RADIUS server entry configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify user feature and radius category.
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
    user_radius:
        description:
            - RADIUS server entry configuration.
        default: null
        type: dict
        suboptions:
            acct_fast_framedip_detect:
                description:
                    - Time in seconds ( ) for Accounting message Framed-IP detection from DHCP Snooping.
                type: int
            acct_interim_interval:
                description:
                    - Time in seconds ( ) between each accounting interim update message.
                type: int
            acct_server:
                description:
                    - Additional accounting servers.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID (0 - 4294967295).
                        type: int
                    port:
                        description:
                            -  RADIUS accounting port number.
                        type: int
                    secret:
                        description:
                            - Secret key.
                        type: str
                    server:
                        description:
                            - Server IP address.
                        type: str
                    status:
                        description:
                            -  Enable/disable Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            addr_mode:
                description:
                    - Address mode (IPv4 or IPv6).
                type: str
                choices:
                    - 'ipv4'
                    - 'ipv6'
            all_usergroup:
                description:
                    - Enable/disable automatic inclusion of this RADIUS server to all user groups.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            auth_type:
                description:
                    - Authentication protocol.
                type: str
                choices:
                    - 'auto'
                    - 'ms_chap_v2'
                    - 'ms_chap'
                    - 'chap'
                    - 'pap'
            frame_mtu_size:
                description:
                    - Frame MTU Size.
                type: int
            link_monitor:
                description:
                    - Enable/disable RADIUS link-monitor service from this server.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            link_monitor_interval:
                description:
                    - Time in seconds ( ) for the link-monitor interval
                type: int
            name:
                description:
                    - RADIUS server entry name.
                required: true
                type: str
            nas_ip:
                description:
                    - NAS IPv4 for the RADIUS request.
                type: str
            nas_ip6:
                description:
                    - NAS IPv6 for the RADIUS request.
                type: str
            radius_coa:
                description:
                    - Enable/disable RADIUS CoA services from this server.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            radius_coa_secret:
                description:
                    - Secret key to access the local Radius CoA server.
                type: str
            radius_port:
                description:
                    - Local RADIUS service port number.
                type: int
            secondary_secret:
                description:
                    - Secret key to access the secondary server.
                type: str
            secondary_server:
                description:
                    - Secondary RADIUS domain name or IP address.
                type: str
            secret:
                description:
                    - Secret key to access the primary server.
                type: str
            server:
                description:
                    - Primary server domain name or IP address.
                type: str
            service_type:
                description:
                    - Radius Service Type.
                type: str
                choices:
                    - 'login'
                    - 'framed'
                    - 'callback-login'
                    - 'callback-framed'
                    - 'outbound'
                    - 'administrative'
                    - 'nas-prompt'
                    - 'authenticate-only'
                    - 'callback-nas-prompt'
                    - 'call-check'
                    - 'callback-administrative'
            source_ip:
                description:
                    - Source IPv4 for communications to RADIUS server.
                type: str
            source_ip6:
                description:
                    - Source IPv6 for communications to RADIUS server.
                type: str
"""

EXAMPLES = """
- name: RADIUS server entry configuration.
  fortinet.fortiswitch.fortiswitch_user_radius:
      state: "present"
      user_radius:
          acct_fast_framedip_detect: "300"
          acct_interim_interval: "43200"
          acct_server:
              -
                  id: "6"
                  port: "7"
                  secret: "<your_own_value>"
                  server: "192.168.100.40"
                  status: "enable"
          addr_mode: "ipv4"
          all_usergroup: "disable"
          auth_type: "auto"
          frame_mtu_size: "750"
          link_monitor: "disable"
          link_monitor_interval: "60"
          name: "default_name_17"
          nas_ip: "<your_own_value>"
          nas_ip6: "<your_own_value>"
          radius_coa: "disable"
          radius_coa_secret: "<your_own_value>"
          radius_port: "22"
          secondary_secret: "<your_own_value>"
          secondary_server: "<your_own_value>"
          secret: "<your_own_value>"
          server: "192.168.100.40"
          service_type: "login"
          source_ip: "<your_own_value>"
          source_ip6: "<your_own_value>"
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


def filter_user_radius_data(json):
    option_list = [
        "acct_fast_framedip_detect",
        "acct_interim_interval",
        "acct_server",
        "addr_mode",
        "all_usergroup",
        "auth_type",
        "frame_mtu_size",
        "link_monitor",
        "link_monitor_interval",
        "name",
        "nas_ip",
        "nas_ip6",
        "radius_coa",
        "radius_coa_secret",
        "radius_port",
        "secondary_secret",
        "secondary_server",
        "secret",
        "server",
        "service_type",
        "source_ip",
        "source_ip6",
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


def user_radius(data, fos, check_mode=False):
    state = data.get("state", None)

    user_radius_data = data["user_radius"]

    filtered_data = filter_user_radius_data(user_radius_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("user", "radius", filtered_data)
        current_data = fos.get("user", "radius", mkey=mkey)
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
            "user",
            "radius",
            data=filtered_data,
        )

    elif state == "absent":
        return fos.delete("user", "radius", mkey=filtered_data["name"])
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


def fortiswitch_user(data, fos, check_mode):
    fos.do_member_operation("user", "radius")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["user_radius"]:
        resp = user_radius(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_radius"))
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
        "radius_coa": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
            "name": "radius-coa",
            "help": "Enable/disable RADIUS CoA services from this server.",
            "category": "unitary",
        },
        "link_monitor_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "link-monitor-interval",
            "help": "Time in seconds ( default 600 ) for the link-monitor interval",
            "category": "unitary",
        },
        "secondary_secret": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "secondary-secret",
            "help": "Secret key to access the secondary server.",
            "category": "unitary",
        },
        "source_ip6": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "source-ip6",
            "help": "Source IPv6 for communications to RADIUS server.",
            "category": "unitary",
        },
        "nas_ip6": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "nas-ip6",
            "help": "NAS IPv6 for the RADIUS request.",
            "category": "unitary",
        },
        "acct_interim_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "acct-interim-interval",
            "help": "Time in seconds ( default 600 ) between each accounting interim update message.",
            "category": "unitary",
        },
        "source_ip": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "source-ip",
            "help": "Source IPv4 for communications to RADIUS server.",
            "category": "unitary",
        },
        "auth_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto"},
                {"value": "ms_chap_v2"},
                {"value": "ms_chap"},
                {"value": "chap"},
                {"value": "pap"},
            ],
            "name": "auth-type",
            "help": "Authentication protocol.",
            "category": "unitary",
        },
        "all_usergroup": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
            "name": "all-usergroup",
            "help": "Enable/disable automatic inclusion of this RADIUS server to all user groups.",
            "category": "unitary",
        },
        "secret": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "secret",
            "help": "Secret key to access the primary server.",
            "category": "unitary",
        },
        "nas_ip": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "nas-ip",
            "help": "NAS IPv4 for the RADIUS request.",
            "category": "unitary",
        },
        "link_monitor": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
            "name": "link-monitor",
            "help": "Enable/disable RADIUS link-monitor service from this server.",
            "category": "unitary",
        },
        "acct_fast_framedip_detect": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "acct-fast-framedip-detect",
            "help": "Time in seconds ( default 4 ) for Accounting message Framed-IP detection from DHCP Snooping.",
            "category": "unitary",
        },
        "frame_mtu_size": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "frame-mtu-size",
            "help": "Frame MTU Size.",
            "category": "unitary",
        },
        "secondary_server": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "secondary-server",
            "help": "Secondary RADIUS domain name or IP address.",
            "category": "unitary",
        },
        "service_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "login"},
                {"value": "framed"},
                {"value": "callback-login"},
                {"value": "callback-framed"},
                {"value": "outbound"},
                {"value": "administrative"},
                {"value": "nas-prompt"},
                {"value": "authenticate-only"},
                {"value": "callback-nas-prompt"},
                {"value": "call-check"},
                {"value": "callback-administrative"},
            ],
            "name": "service-type",
            "help": "Radius Service Type.",
            "category": "unitary",
        },
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "RADIUS server entry name.",
            "category": "unitary",
        },
        "server": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "server",
            "help": "Primary server domain name or IP address.",
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
        "radius_coa_secret": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "radius-coa-secret",
            "help": "Secret key to access the local Radius CoA server.",
            "category": "unitary",
        },
        "acct_server": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "status",
                    "help": " Enable/disable Status.",
                    "category": "unitary",
                },
                "secret": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "secret",
                    "help": "Secret key.",
                    "category": "unitary",
                },
                "port": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "port",
                    "help": " RADIUS accounting port number.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "ID (0 - 4294967295).",
                    "category": "unitary",
                },
                "server": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "server",
                    "help": "Server IP address.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "acct-server",
            "help": "Additional accounting servers.",
            "mkey": "id",
            "category": "table",
        },
        "radius_port": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "radius-port",
            "help": "Local RADIUS service port number.",
            "category": "unitary",
        },
    },
    "v_range": [["v7.0.0", ""]],
    "name": "radius",
    "help": "RADIUS server entry configuration.",
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
        "user_radius": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_radius"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["user_radius"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "user_radius"
        )
        is_error, has_changed, result, diff = fortiswitch_user(
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
