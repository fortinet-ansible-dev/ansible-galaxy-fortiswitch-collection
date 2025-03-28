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
module: fortiswitch_alertemail_setting
short_description: Alertemail setting configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify alertemail feature and setting category.
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

    alertemail_setting:
        description:
            - Alertemail setting configuration.
        default: null
        type: dict
        suboptions:
            admin_login_logs:
                description:
                    - Admin-login-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            alert_interval:
                description:
                    - Set Alert alert interval in minutes.
                type: int
            amc_interface_bypass_mode:
                description:
                    - Amc-interface-bypass-mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            antivirus_logs:
                description:
                    - Antivirus-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            configuration_changes_logs:
                description:
                    - Configuration-changes-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            critical_interval:
                description:
                    - Set Critical alert interval in minutes.
                type: int
            debug_interval:
                description:
                    - Set Debug alert interval in minutes.
                type: int
            email_interval:
                description:
                    - Interval between each email.
                type: int
            emergency_interval:
                description:
                    - Set Emergency alert interval in minutes.
                type: int
            error_interval:
                description:
                    - Set Error alert interval in minutes.
                type: int
            FDS_license_expiring_days:
                description:
                    - Send alertemail before these days FortiGuard license expire (1-100).
                type: int
            FDS_license_expiring_warning:
                description:
                    - FDS-license-expiring-warning.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            FDS_update_logs:
                description:
                    - FDS-update-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            filter_mode:
                description:
                    - Filter mode.
                type: str
                choices:
                    - 'category'
                    - 'threshold'
            firewall_authentication_failure_logs:
                description:
                    - Firewall-authentication-failure-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortiguard_log_quota_warning:
                description:
                    - Fortiguard-log-quota-warning.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            HA_logs:
                description:
                    - HA-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            information_interval:
                description:
                    - Set Information alert interval in minutes.
                type: int
            IPS_logs:
                description:
                    - IPS-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            IPsec_errors_logs:
                description:
                    - IPsec-errors-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_disk_usage:
                description:
                    - Send alertemail when disk usage exceeds this threshold (1-99).
                type: int
            log_disk_usage_warning:
                description:
                    - Log-disk-usage-warning.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mailto1:
                description:
                    - Set destination email address 1.
                type: str
            mailto2:
                description:
                    - Set destination email address 2.
                type: str
            mailto3:
                description:
                    - Set destination email address 3.
                type: str
            notification_interval:
                description:
                    - Set Notification alert interval in minutes.
                type: int
            PPP_errors_logs:
                description:
                    - PPP-errors-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            severity:
                description:
                    - The least severity level to log.
                type: str
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            sslvpn_authentication_errors_logs:
                description:
                    - Sslvpn-authentication-errors-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            username:
                description:
                    - Set email from address.
                type: str
            violation_traffic_logs:
                description:
                    - Violation-traffic-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            warning_interval:
                description:
                    - Set Warning alert interval in minutes.
                type: int
            webfilter_logs:
                description:
                    - Webfilter-logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Alertemail setting configuration.
  fortinet.fortiswitch.fortiswitch_alertemail_setting:
      alertemail_setting:
          admin_login_logs: "enable"
          alert_interval: "1073741823"
          amc_interface_bypass_mode: "enable"
          antivirus_logs: "enable"
          configuration_changes_logs: "enable"
          critical_interval: "1073741823"
          debug_interval: "1073741823"
          email_interval: "49999"
          emergency_interval: "1073741823"
          error_interval: "1073741823"
          FDS_license_expiring_days: "50"
          FDS_license_expiring_warning: "enable"
          FDS_update_logs: "enable"
          filter_mode: "category"
          firewall_authentication_failure_logs: "enable"
          fortiguard_log_quota_warning: "enable"
          HA_logs: "enable"
          information_interval: "1073741823"
          IPS_logs: "enable"
          IPsec_errors_logs: "enable"
          local_disk_usage: "49"
          log_disk_usage_warning: "enable"
          mailto1: "<your_own_value>"
          mailto2: "<your_own_value>"
          mailto3: "<your_own_value>"
          notification_interval: "1073741823"
          PPP_errors_logs: "enable"
          severity: "emergency"
          sslvpn_authentication_errors_logs: "enable"
          username: "<your_own_value>"
          violation_traffic_logs: "enable"
          warning_interval: "1073741823"
          webfilter_logs: "enable"
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


def filter_alertemail_setting_data(json):
    option_list = [
        "admin_login_logs",
        "alert_interval",
        "amc_interface_bypass_mode",
        "antivirus_logs",
        "configuration_changes_logs",
        "critical_interval",
        "debug_interval",
        "email_interval",
        "emergency_interval",
        "error_interval",
        "FDS_license_expiring_days",
        "FDS_license_expiring_warning",
        "FDS_update_logs",
        "filter_mode",
        "firewall_authentication_failure_logs",
        "fortiguard_log_quota_warning",
        "HA_logs",
        "information_interval",
        "IPS_logs",
        "IPsec_errors_logs",
        "local_disk_usage",
        "log_disk_usage_warning",
        "mailto1",
        "mailto2",
        "mailto3",
        "notification_interval",
        "PPP_errors_logs",
        "severity",
        "sslvpn_authentication_errors_logs",
        "username",
        "violation_traffic_logs",
        "warning_interval",
        "webfilter_logs",
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


def alertemail_setting(data, fos, check_mode=False):
    state = data.get("state", None)

    alertemail_setting_data = data["alertemail_setting"]

    filtered_data = filter_alertemail_setting_data(alertemail_setting_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("alertemail", "setting", filtered_data)
        current_data = fos.get("alertemail", "setting", mkey=mkey)
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
        "alertemail",
        "setting",
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


def fortiswitch_alertemail(data, fos, check_mode):
    fos.do_member_operation("alertemail", "setting")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["alertemail_setting"]:
        resp = alertemail_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("alertemail_setting"))
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
        "email_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "email-interval",
            "help": "Interval between each email.",
            "category": "unitary",
        },
        "critical_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "critical-interval",
            "help": "Set Critical alert interval in minutes.",
            "category": "unitary",
        },
        "debug_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "debug-interval",
            "help": "Set Debug alert interval in minutes.",
            "category": "unitary",
        },
        "error_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "error-interval",
            "help": "Set Error alert interval in minutes.",
            "category": "unitary",
        },
        "sslvpn_authentication_errors_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "sslvpn-authentication-errors-logs",
            "help": "Sslvpn-authentication-errors-logs.",
            "category": "unitary",
        },
        "IPsec_errors_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "IPsec-errors-logs",
            "help": "IPsec-errors-logs.",
            "category": "unitary",
        },
        "antivirus_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "antivirus-logs",
            "help": "Antivirus-logs.",
            "category": "unitary",
        },
        "warning_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "warning-interval",
            "help": "Set Warning alert interval in minutes.",
            "category": "unitary",
        },
        "firewall_authentication_failure_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "firewall-authentication-failure-logs",
            "help": "Firewall-authentication-failure-logs.",
            "category": "unitary",
        },
        "severity": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "emergency"},
                {"value": "alert"},
                {"value": "critical"},
                {"value": "error"},
                {"value": "warning"},
                {"value": "notification"},
                {"value": "information"},
                {"value": "debug"},
            ],
            "name": "severity",
            "help": "The least severity level to log.",
            "category": "unitary",
        },
        "emergency_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "emergency-interval",
            "help": "Set Emergency alert interval in minutes.",
            "category": "unitary",
        },
        "FDS_license_expiring_warning": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "FDS-license-expiring-warning",
            "help": "FDS-license-expiring-warning.",
            "category": "unitary",
        },
        "configuration_changes_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "configuration-changes-logs",
            "help": "Configuration-changes-logs.",
            "category": "unitary",
        },
        "notification_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "notification-interval",
            "help": "Set Notification alert interval in minutes.",
            "category": "unitary",
        },
        "information_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "information-interval",
            "help": "Set Information alert interval in minutes.",
            "category": "unitary",
        },
        "FDS_license_expiring_days": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "FDS-license-expiring-days",
            "help": "Send alertemail before these days FortiGuard license expire (1-100).",
            "category": "unitary",
        },
        "admin_login_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "admin-login-logs",
            "help": "Admin-login-logs.",
            "category": "unitary",
        },
        "username": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "username",
            "help": "Set email from address.",
            "category": "unitary",
        },
        "alert_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "alert-interval",
            "help": "Set Alert alert interval in minutes.",
            "category": "unitary",
        },
        "mailto1": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "mailto1",
            "help": "Set destination email address 1.",
            "category": "unitary",
        },
        "mailto3": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "mailto3",
            "help": "Set destination email address 3.",
            "category": "unitary",
        },
        "mailto2": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "mailto2",
            "help": "Set destination email address 2.",
            "category": "unitary",
        },
        "webfilter_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "webfilter-logs",
            "help": "Webfilter-logs.",
            "category": "unitary",
        },
        "fortiguard_log_quota_warning": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "fortiguard-log-quota-warning",
            "help": "Fortiguard-log-quota-warning.",
            "category": "unitary",
        },
        "filter_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "category"}, {"value": "threshold"}],
            "name": "filter-mode",
            "help": "Filter mode.",
            "category": "unitary",
        },
        "IPS_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "IPS-logs",
            "help": "IPS-logs.",
            "category": "unitary",
        },
        "HA_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "HA-logs",
            "help": "HA-logs.",
            "category": "unitary",
        },
        "local_disk_usage": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "local-disk-usage",
            "help": "Send alertemail when disk usage exceeds this threshold (1-99).",
            "category": "unitary",
        },
        "PPP_errors_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "PPP-errors-logs",
            "help": "PPP-errors-logs.",
            "category": "unitary",
        },
        "violation_traffic_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "violation-traffic-logs",
            "help": "Violation-traffic-logs.",
            "category": "unitary",
        },
        "log_disk_usage_warning": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "log-disk-usage-warning",
            "help": "Log-disk-usage-warning.",
            "category": "unitary",
        },
        "FDS_update_logs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "FDS-update-logs",
            "help": "FDS-update-logs.",
            "category": "unitary",
        },
        "amc_interface_bypass_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "amc-interface-bypass-mode",
            "help": "Amc-interface-bypass-mode.",
            "category": "unitary",
        },
    },
    "name": "setting",
    "help": "Alertemail setting configuration.",
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
        "alertemail_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["alertemail_setting"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["alertemail_setting"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "alertemail_setting"
        )
        is_error, has_changed, result, diff = fortiswitch_alertemail(
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
