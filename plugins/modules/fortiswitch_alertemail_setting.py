#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019-2020 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortiswitch_alertemail_setting
short_description: Alertemail setting configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify alertemail feature and setting category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v7.0.0
version_added: "2.11"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:

requirements:
    - ansible>=2.11
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
                    - enable
                    - disable
            alert_interval:
                description:
                    - Set Alert alert interval in minutes.
                type: int
            amc_interface_bypass_mode:
                description:
                    - Amc-interface-bypass-mode.
                type: str
                choices:
                    - enable
                    - disable
            antivirus_logs:
                description:
                    - Antivirus-logs.
                type: str
                choices:
                    - enable
                    - disable
            configuration_changes_logs:
                description:
                    - Configuration-changes-logs.
                type: str
                choices:
                    - enable
                    - disable
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
                    - enable
                    - disable
            FDS_update_logs:
                description:
                    - FDS-update-logs.
                type: str
                choices:
                    - enable
                    - disable
            filter_mode:
                description:
                    - Filter mode.
                type: str
                choices:
                    - category
                    - threshold
            firewall_authentication_failure_logs:
                description:
                    - Firewall-authentication-failure-logs.
                type: str
                choices:
                    - enable
                    - disable
            fortiguard_log_quota_warning:
                description:
                    - Fortiguard-log-quota-warning.
                type: str
                choices:
                    - enable
                    - disable
            HA_logs:
                description:
                    - HA-logs.
                type: str
                choices:
                    - enable
                    - disable
            information_interval:
                description:
                    - Set Information alert interval in minutes.
                type: int
            IPS_logs:
                description:
                    - IPS-logs.
                type: str
                choices:
                    - enable
                    - disable
            IPsec_errors_logs:
                description:
                    - IPsec-errors-logs.
                type: str
                choices:
                    - enable
                    - disable
            local_disk_usage:
                description:
                    - Send alertemail when disk usage exceeds this threshold (1-99).
                type: int
            log_disk_usage_warning:
                description:
                    - Log-disk-usage-warning.
                type: str
                choices:
                    - enable
                    - disable
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
                    - enable
                    - disable
            severity:
                description:
                    - The least severity level to log.
                type: str
                choices:
                    - emergency
                    - alert
                    - critical
                    - error
                    - warning
                    - notification
                    - information
                    - debug
            sslvpn_authentication_errors_logs:
                description:
                    - Sslvpn-authentication-errors-logs.
                type: str
                choices:
                    - enable
                    - disable
            username:
                description:
                    - Set email from address.
                type: str
            violation_traffic_logs:
                description:
                    - Violation-traffic-logs.
                type: str
                choices:
                    - enable
                    - disable
            warning_interval:
                description:
                    - Set Warning alert interval in minutes.
                type: int
            webfilter_logs:
                description:
                    - Webfilter-logs.
                type: str
                choices:
                    - enable
                    - disable
'''

EXAMPLES = '''
- hosts: fortiswitch01
  collections:
    - fortinet.fortiswitch
  connection: httpapi
  vars:
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: no
   ansible_httpapi_port: 443
  tasks:
  - name: Alertemail setting configuration.
    fortiswitch_alertemail_setting:
      state: "present"
      alertemail_setting:
        admin_login_logs: "enable"
        alert_interval: "4"
        amc_interface_bypass_mode: "enable"
        antivirus_logs: "enable"
        configuration_changes_logs: "enable"
        critical_interval: "8"
        debug_interval: "9"
        email_interval: "10"
        emergency_interval: "11"
        error_interval: "12"
        FDS_license_expiring_days: "13"
        FDS_license_expiring_warning: "enable"
        FDS_update_logs: "enable"
        filter_mode: "category"
        firewall_authentication_failure_logs: "enable"
        fortiguard_log_quota_warning: "enable"
        HA_logs: "enable"
        information_interval: "20"
        IPS_logs: "enable"
        IPsec_errors_logs: "enable"
        local_disk_usage: "23"
        log_disk_usage_warning: "enable"
        mailto1: "<your_own_value>"
        mailto2: "<your_own_value>"
        mailto3: "<your_own_value>"
        notification_interval: "28"
        PPP_errors_logs: "enable"
        severity: "emergency"
        sslvpn_authentication_errors_logs: "enable"
        username: "<your_own_value>"
        violation_traffic_logs: "enable"
        warning_interval: "34"
        webfilter_logs: "enable"

'''

RETURN = '''
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

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import FortiOSHandler
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import schema_to_module_spec
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import check_schema_versioning
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG


def filter_alertemail_setting_data(json):
    option_list = ['admin_login_logs', 'alert_interval', 'amc_interface_bypass_mode',
                   'antivirus_logs', 'configuration_changes_logs', 'critical_interval',
                   'debug_interval', 'email_interval', 'emergency_interval',
                   'error_interval', 'FDS_license_expiring_days', 'FDS_license_expiring_warning',
                   'FDS_update_logs', 'filter_mode', 'firewall_authentication_failure_logs',
                   'fortiguard_log_quota_warning', 'HA_logs', 'information_interval',
                   'IPS_logs', 'IPsec_errors_logs', 'local_disk_usage',
                   'log_disk_usage_warning', 'mailto1', 'mailto2',
                   'mailto3', 'notification_interval', 'PPP_errors_logs',
                   'severity', 'sslvpn_authentication_errors_logs', 'username',
                   'violation_traffic_logs', 'warning_interval', 'webfilter_logs']
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
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def alertemail_setting(data, fos):
    alertemail_setting_data = data['alertemail_setting']
    filtered_data = underscore_to_hyphen(filter_alertemail_setting_data(alertemail_setting_data))

    return fos.set('alertemail',
                   'setting',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_alertemail(data, fos):

    fos.do_member_operation('alertemail_setting')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['alertemail_setting']:
        resp = alertemail_setting(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('alertemail_setting'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp


versioned_schema = {
    "type": "dict",
    "children": {
        "admin_login_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "antivirus_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "configuration_changes_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "IPsec_errors_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "severity": {
            "type": "string",
            "options": [
                {
                    "value": "emergency",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "alert",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "critical",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "error",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "warning",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "notification",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "information",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "debug",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "notification_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "local_disk_usage": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "amc_interface_bypass_mode": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "FDS_update_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "sslvpn_authentication_errors_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "PPP_errors_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "username": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "mailto1": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "mailto3": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "mailto2": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "fortiguard_log_quota_warning": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "warning_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "firewall_authentication_failure_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "alert_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "critical_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "debug_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "email_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "FDS_license_expiring_days": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "HA_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "IPS_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "emergency_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "log_disk_usage_warning": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "violation_traffic_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "information_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "webfilter_logs": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "error_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "FDS_license_expiring_warning": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "filter_mode": {
            "type": "string",
            "options": [
                {
                    "value": "category",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "threshold",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        }
    },
    "revisions": {
        "v7.0.0": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
    fields = {
        "enable_log": {"required": False, "type": bool},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "alertemail_setting": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["alertemail_setting"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["alertemail_setting"]['options'][attribute_name]['required'] = True

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "alertemail_setting")

        is_error, has_changed, result = fortiswitch_alertemail(module.params, fos)

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortiSwitch system and your playbook, see more details by specifying option -vvv")

    if not is_error:
        if versions_check_result and versions_check_result['matched'] is False:
            module.exit_json(changed=has_changed, version_check_warning=versions_check_result, meta=result)
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        if versions_check_result and versions_check_result['matched'] is False:
            module.fail_json(msg="Error in repo", version_check_warning=versions_check_result, meta=result)
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
