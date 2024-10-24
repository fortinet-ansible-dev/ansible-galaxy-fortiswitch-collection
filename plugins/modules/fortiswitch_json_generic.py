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
module: fortiswitch_json_generic
short_description: Configure Fortinet's FortiSwitch with json generic method.
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify json feature and generic category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FortiSwitch v7.6.0
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
    json_generic:
        description:
            - json generic
        default: null
        type: dict
        suboptions:
            dictbody:
                description:
                    - Body with YAML list of key/value format
                type: dict
            jsonbody:
                description:
                    - Body with JSON string format, will always give priority to jsonbody
                type: str
            method:
                description:
                    - HTTP methods
                type: str
                required: true
                choices:
                    - 'GET'
                    - 'PUT'
                    - 'POST'
                    - 'DELETE'
            path:
                description:
                    - URL path, e.g./api/v2/cmdb/system/global
                type: str
                required: true
            specialparams:
                description:
                    - Extra URL parameters, e.g.start=1&count=10
                type: str
"""

EXAMPLES = """
    - name: test add with string
      fortiswitch_json_generic:
        enable_log: True
        json_generic:
          method: "PUT"
          path: "/api/v2/cmdb/system/global"
          jsonbody: |
            {
            "timezone": "04"
            }
      register: info

    - name: display vars
      debug: msg="{{info}}"
"""

RETURN = """
build:
  description: Build number of the fortiswitch image
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
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
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

from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)

import json


def login(data, fos):
    host = data["host"]
    username = data["username"]
    password = data["password"]
    ssl_verify = data["ssl_verify"]

    fos.debug("on")
    if "https" in data and not data["https"]:
        fos.https("off")
    else:
        fos.https("on")

    fos.login(host, username, password, verify=ssl_verify)


def json_generic(data, fos):
    json_generic_data = data["json_generic"]

    # Give priority to jsonbody
    data = ""
    if json_generic_data["jsonbody"]:
        try:
            data = json.loads(json_generic_data["jsonbody"])
        except Exception as e:
            fos._module.fail_json("invalid json content: %s" % (e))
    else:
        if json_generic_data["dictbody"]:
            data = json_generic_data["dictbody"]

    return fos.jsonraw(
        json_generic_data["method"],
        json_generic_data["path"],
        data=data,
        specific_params=json_generic_data["specialparams"],
    )


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and "http_status" in resp
        and resp["http_status"] == 404
    )


def fortios_json(data, fos):

    if data["json_generic"]:
        resp = json_generic(data, fos)

    return not is_successful_status(resp), resp["status"] == "success", resp


def main():
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "json_generic": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {
                "dictbody": {"required": False, "type": "dict"},
                "jsonbody": {"required": False, "type": "str"},
                "method": {
                    "required": True,
                    "type": "str",
                    "choices": ["GET", "PUT", "POST", "DELETE"],
                },
                "path": {"required": True, "type": "str"},
                "specialparams": {"required": False, "type": "str"},
            },
        },
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)

    is_error = False
    has_changed = False
    result = None

    if module._socket_path:
        connection = Connection(module._socket_path)
        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module)
        is_error, has_changed, result = fortios_json(module.params, fos)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(
            msg="Unable to precess the request, please provide correct parameters and make sure the path exists.",
            meta=result,
        )


if __name__ == "__main__":
    main()
