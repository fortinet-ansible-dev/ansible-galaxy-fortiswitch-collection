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
module: fortiswitch_system_admin
short_description: Administrative user configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and admin category.
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
    system_admin:
        description:
            - Administrative user configuration.
        default: null
        type: dict
        suboptions:
            accprofile:
                description:
                    - Administrative user access profile.
                type: str
            accprofile_override:
                description:
                    - Enable/disable remote authentication server to override access profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            allow_remove_admin_session:
                description:
                    - Enable/disable privileged administrative users to remove administrative sessions.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            comments:
                description:
                    - Comment.
                type: str
            email_address:
                description:
                    - Email address.
                type: str
            first_name:
                description:
                    - First name.
                type: str
            force_password_change:
                description:
                    - Enable/disable forcing of password change on next login.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            hidden:
                description:
                    - Administrative user hidden attribute.
                type: int
            ip6_trusthost1:
                description:
                    - Trusted host one IP address .
                type: str
            ip6_trusthost10:
                description:
                    - Trusted host one IP address .
                type: str
            ip6_trusthost2:
                description:
                    - Trusted host one IP address .
                type: str
            ip6_trusthost3:
                description:
                    - Trusted host one IP address .
                type: str
            ip6_trusthost4:
                description:
                    - Trusted host one IP address .
                type: str
            ip6_trusthost5:
                description:
                    - Trusted host one IP address .
                type: str
            ip6_trusthost6:
                description:
                    - Trusted host one IP address .
                type: str
            ip6_trusthost7:
                description:
                    - Trusted host one IP address .
                type: str
            ip6_trusthost8:
                description:
                    - Trusted host one IP address .
                type: str
            ip6_trusthost9:
                description:
                    - Trusted host one IP address .
                type: str
            is_admin:
                description:
                    - User has administrative privileges.
                type: int
            last_name:
                description:
                    - Last name.
                type: str
            mobile_number:
                description:
                    - Mobile number.
                type: str
            name:
                description:
                    - Adminstrative user name.
                required: true
                type: str
            pager_number:
                description:
                    - Pager number.
                type: str
            password:
                description:
                    - Remote authentication password.
                type: str
            password_expire:
                description:
                    - Password expire time.
                type: str
            peer_auth:
                description:
                    - Enable/disable peer authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            peer_group:
                description:
                    - Peer group name.
                type: str
            phone_number:
                description:
                    - Phone number.
                type: str
            remote_auth:
                description:
                    - Enable/disable remote authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            remote_group:
                description:
                    - Remote authentication group name.
                type: str
            schedule:
                description:
                    - Schedule name.
                type: str
            ssh_public_key1:
                description:
                    - SSH public key1.
                type: str
            ssh_public_key2:
                description:
                    - SSH public key2.
                type: str
            ssh_public_key3:
                description:
                    - SSH public key3.
                type: str
            trusthost1:
                description:
                    - Trusted host one IP address .
                type: str
            trusthost10:
                description:
                    - Trusted host one IP address .
                type: str
            trusthost2:
                description:
                    - Trusted host one IP address .
                type: str
            trusthost3:
                description:
                    - Trusted host one IP address .
                type: str
            trusthost4:
                description:
                    - Trusted host one IP address .
                type: str
            trusthost5:
                description:
                    - Trusted host one IP address .
                type: str
            trusthost6:
                description:
                    - Trusted host one IP address .
                type: str
            trusthost7:
                description:
                    - Trusted host one IP address .
                type: str
            trusthost8:
                description:
                    - Trusted host one IP address .
                type: str
            trusthost9:
                description:
                    - Trusted host one IP address .
                type: str
            vdom:
                description:
                    - Virtual domain name.
                type: str
            wildcard:
                description:
                    - Enable/disable wildcard RADIUS authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wildcard_fallback:
                description:
                    - Enable/disable attempting authentication against wildcard accounts if authenticating this account fails.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Administrative user configuration.
  fortinet.fortiswitch.fortiswitch_system_admin:
      state: "present"
      system_admin:
          accprofile: "<your_own_value> (source system.accprofile.name)"
          accprofile_override: "enable"
          allow_remove_admin_session: "enable"
          comments: "<your_own_value>"
          Email address.: "<your_own_value>"
          First name.: "<your_own_value>"
          force_password_change: "enable"
          hidden: "10"
          ip6_trusthost1: "<your_own_value>"
          ip6_trusthost10: "<your_own_value>"
          ip6_trusthost2: "<your_own_value>"
          ip6_trusthost3: "<your_own_value>"
          ip6_trusthost4: "<your_own_value>"
          ip6_trusthost5: "<your_own_value>"
          ip6_trusthost6: "<your_own_value>"
          ip6_trusthost7: "<your_own_value>"
          ip6_trusthost8: "<your_own_value>"
          ip6_trusthost9: "<your_own_value>"
          is_admin: "21"
          Last name.: "<your_own_value>"
          Mobile number.: "<your_own_value>"
          name: "default_name_24"
          Pager number.: "<your_own_value>"
          password: "<your_own_value>"
          password_expire: "<your_own_value>"
          peer_auth: "enable"
          peer_group: "<your_own_value>"
          Phone number.: "<your_own_value>"
          remote_auth: "enable"
          remote_group: "<your_own_value>"
          schedule: "<your_own_value>"
          ssh_public_key1: "<your_own_value>"
          ssh_public_key2: "<your_own_value>"
          ssh_public_key3: "<your_own_value>"
          trusthost1: "<your_own_value>"
          trusthost10: "<your_own_value>"
          trusthost2: "<your_own_value>"
          trusthost3: "<your_own_value>"
          trusthost4: "<your_own_value>"
          trusthost5: "<your_own_value>"
          trusthost6: "<your_own_value>"
          trusthost7: "<your_own_value>"
          trusthost8: "<your_own_value>"
          trusthost9: "<your_own_value>"
          vdom: "<your_own_value> (source system.vdom.name)"
          wildcard: "enable"
          wildcard_fallback: "enable"
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


def filter_system_admin_data(json):
    option_list = [
        "accprofile",
        "accprofile_override",
        "allow_remove_admin_session",
        "comments",
        "Email address.",
        "First name.",
        "force_password_change",
        "hidden",
        "ip6_trusthost1",
        "ip6_trusthost10",
        "ip6_trusthost2",
        "ip6_trusthost3",
        "ip6_trusthost4",
        "ip6_trusthost5",
        "ip6_trusthost6",
        "ip6_trusthost7",
        "ip6_trusthost8",
        "ip6_trusthost9",
        "is_admin",
        "Last name.",
        "Mobile number.",
        "name",
        "Pager number.",
        "password",
        "password_expire",
        "peer_auth",
        "peer_group",
        "Phone number.",
        "remote_auth",
        "remote_group",
        "schedule",
        "ssh_public_key1",
        "ssh_public_key2",
        "ssh_public_key3",
        "trusthost1",
        "trusthost10",
        "trusthost2",
        "trusthost3",
        "trusthost4",
        "trusthost5",
        "trusthost6",
        "trusthost7",
        "trusthost8",
        "trusthost9",
        "vdom",
        "wildcard",
        "wildcard_fallback",
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


def valid_attr_to_invalid_attr(data):
    speciallist = {
        "Email address.": "email_address",
        "First name.": "first_name",
        "Last name.": "last_name",
        "Mobile number.": "mobile_number",
        "Pager number.": "pager_number",
        "Phone number.": "phone_number",
    }

    for k, v in speciallist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return data


def system_admin(data, fos, check_mode=False):
    state = data.get("state", None)

    system_admin_data = data["system_admin"]

    filtered_data = filter_system_admin_data(system_admin_data)
    filtered_data = underscore_to_hyphen(filtered_data)
    converted_data = valid_attr_to_invalid_attrs(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system", "admin", filtered_data)
        current_data = fos.get("system", "admin", mkey=mkey)
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
            "admin",
            data=converted_data,
        )

    elif state == "absent":
        return fos.delete("system", "admin", mkey=filtered_data["name"])
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
    fos.do_member_operation("system", "admin")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["system_admin"]:
        resp = system_admin(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_admin"))
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
        "ip6_trusthost2": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ip6-trusthost2",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "ip6_trusthost3": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ip6-trusthost3",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "is_admin": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "is-admin",
            "help": "User has administrative privileges.",
            "category": "unitary",
        },
        "ip6_trusthost1": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ip6-trusthost1",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "ip6_trusthost6": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ip6-trusthost6",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "ip6_trusthost7": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ip6-trusthost7",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "ip6_trusthost4": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ip6-trusthost4",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "ip6_trusthost5": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ip6-trusthost5",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "accprofile_override": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "accprofile-override",
            "help": "Enable/disable remote authentication server to override access profile.",
            "category": "unitary",
        },
        "ip6_trusthost8": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ip6-trusthost8",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "ip6_trusthost9": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ip6-trusthost9",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "email_address": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "email_address",
            "help": "Email address.",
            "category": "unitary",
        },
        "accprofile": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "accprofile",
            "help": "Administrative user access profile.",
            "category": "unitary",
        },
        "phone_number": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "phone_number",
            "help": "Phone number.",
            "category": "unitary",
        },
        "force_password_change": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "force-password-change",
            "help": "Enable/disable forcing of password change on next login.",
            "category": "unitary",
        },
        "allow_remove_admin_session": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "allow-remove-admin-session",
            "help": "Enable/disable privileged administrative users to remove administrative sessions.",
            "category": "unitary",
        },
        "mobile_number": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "mobile_number",
            "help": "Mobile number.",
            "category": "unitary",
        },
        "last_name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "last_name",
            "help": "Last name.",
            "category": "unitary",
        },
        "schedule": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "schedule",
            "help": "Schedule name.",
            "category": "unitary",
        },
        "peer_group": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "peer-group",
            "help": "Peer group name.",
            "category": "unitary",
        },
        "comments": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "comments",
            "help": "Comment.",
            "category": "unitary",
        },
        "trusthost10": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trusthost10",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "hidden": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "hidden",
            "help": "Administrative user hidden attribute.",
            "category": "unitary",
        },
        "trusthost8": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trusthost8",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "trusthost9": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trusthost9",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "trusthost6": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trusthost6",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "trusthost7": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trusthost7",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "trusthost4": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trusthost4",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "trusthost5": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trusthost5",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "trusthost2": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trusthost2",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "trusthost3": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trusthost3",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "trusthost1": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trusthost1",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "first_name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "first_name",
            "help": "First name.",
            "category": "unitary",
        },
        "ip6_trusthost10": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ip6-trusthost10",
            "help": "Trusted host one IP address (default = 0.0.0.0 0.0.0.0 to trust all IPs).",
            "category": "unitary",
        },
        "password": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "password",
            "help": "Remote authentication password.",
            "category": "unitary",
        },
        "vdom": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "vdom",
            "help": "Virtual domain name.",
            "category": "unitary",
        },
        "remote_auth": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "remote-auth",
            "help": "Enable/disable remote authentication.",
            "category": "unitary",
        },
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "Adminstrative user name.",
            "category": "unitary",
        },
        "password_expire": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "password-expire",
            "help": "Password expire time.",
            "category": "unitary",
        },
        "remote_group": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "remote-group",
            "help": "Remote authentication group name.",
            "category": "unitary",
        },
        "wildcard": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "wildcard",
            "help": "Enable/disable wildcard RADIUS authentication.",
            "category": "unitary",
        },
        "ssh_public_key1": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ssh-public-key1",
            "help": "SSH public key1.",
            "category": "unitary",
        },
        "ssh_public_key3": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ssh-public-key3",
            "help": "SSH public key3.",
            "category": "unitary",
        },
        "ssh_public_key2": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ssh-public-key2",
            "help": "SSH public key2.",
            "category": "unitary",
        },
        "peer_auth": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "peer-auth",
            "help": "Enable/disable peer authentication.",
            "category": "unitary",
        },
        "pager_number": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "pager_number",
            "help": "Pager number.",
            "category": "unitary",
        },
        "wildcard_fallback": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "wildcard-fallback",
            "help": "Enable/disable attempting authentication against wildcard accounts if authenticating this account fails.",
            "category": "unitary",
        },
    },
    "v_range": [["v7.0.0", ""]],
    "name": "admin",
    "help": "Administrative user configuration.",
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
        "system_admin": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_admin"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_admin"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_admin"
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
