#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortiswitch_log_disk_setting
short_description: Settings for local disk logging in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify log_disk feature and setting category.
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

    log_disk_setting:
        description:
            - Settings for local disk logging.
        default: null
        type: dict
        suboptions:
            diskfull:
                description:
                    - Policy to apply when disk is full.
                type: str
                choices:
                    - 'overwrite'
                    - 'nolog'
            drive_standby_time:
                description:
                    - Power management timeout(0-19800 sec)(0 disable).
                type: int
            full_final_warning_threshold:
                description:
                    - Log full final warning threshold(3-100), the default is 95.
                type: int
            full_first_warning_threshold:
                description:
                    - Log full first warning threshold(1-98), the default is 75.
                type: int
            full_second_warning_threshold:
                description:
                    - Log full second warning threshold(2-99), the default is 90.
                type: int
            log_quota:
                description:
                    - Disk log quota.
                type: int
            max_log_file_size:
                description:
                    - Max log file size in MB before rolling (may not be accurate all the time).
                type: int
            report_quota:
                description:
                    - Report quota.
                type: int
            roll_day:
                description:
                    - Days of week to roll logs.
                type: str
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            roll_schedule:
                description:
                    - Frequency to check log file for rolling.
                type: str
                choices:
                    - 'daily'
                    - 'weekly'
            roll_time:
                description:
                    - 'Time to roll logs [hh:mm].'
                type: str
            source_ip:
                description:
                    - Source IP address of the disk log uploading.
                type: str
            status:
                description:
                    - Enable/disable local disk log.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            upload:
                description:
                    - Whether to upload the log file when rolling.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            upload_delete_files:
                description:
                    - Delete log files after uploading .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            upload_destination:
                description:
                    - Server type.
                type: str
                choices:
                    - 'ftp-server'
            upload_format:
                description:
                    - Upload compact/text logs.
                type: str
                choices:
                    - 'compact'
                    - 'text'
            upload_ssl_conn:
                description:
                    - Enable/disable SSL communication when uploading.
                type: str
                choices:
                    - 'default'
                    - 'high'
                    - 'low'
                    - 'disable'
            uploaddir:
                description:
                    - Log file uploading remote directory.
                type: str
            uploadip:
                description:
                    - IP address of the log uploading server.
                type: str
            uploadpass:
                description:
                    - Password of the user account in the uploading server.
                type: str
            uploadport:
                description:
                    - Port of the log uploading server.
                type: int
            uploadsched:
                description:
                    - Scheduled upload (disable=upload when rolling).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            uploadtime:
                description:
                    - Time of scheduled upload.
                type: int
            uploadtype:
                description:
                    - Types of log files that need to be uploaded.
                type: str
                choices:
                    - 'traffic'
                    - 'event'
                    - 'virus'
                    - 'webfilter'
                    - 'attack'
                    - 'spamfilter'
                    - 'dlp-archive'
                    - 'dlp'
                    - 'app-ctrl'
            uploaduser:
                description:
                    - User account in the uploading server.
                type: str
            uploadzip:
                description:
                    - Compress upload logs.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Settings for local disk logging.
  fortinet.fortiswitch.fortiswitch_log_disk_setting:
      log_disk_setting:
          diskfull: "overwrite"
          drive_standby_time: "4"
          full_final_warning_threshold: "5"
          full_first_warning_threshold: "6"
          full_second_warning_threshold: "7"
          log_quota: "8"
          max_log_file_size: "9"
          report_quota: "10"
          roll_day: "sunday"
          roll_schedule: "daily"
          roll_time: "<your_own_value>"
          source_ip: "<your_own_value>"
          status: "enable"
          upload: "enable"
          upload_delete_files: "enable"
          upload_destination: "ftp-server"
          upload_format: "compact"
          upload_ssl_conn: "default"
          uploaddir: "<your_own_value>"
          uploadip: "<your_own_value>"
          uploadpass: "<your_own_value>"
          uploadport: "24"
          uploadsched: "disable"
          uploadtime: "26"
          uploadtype: "traffic"
          uploaduser: "<your_own_value>"
          uploadzip: "disable"
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
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.data_post_processor import remove_invalid_fields
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import is_same_comparison
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import serialize
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import find_current_values


def filter_log_disk_setting_data(json):
    option_list = ['diskfull', 'drive_standby_time', 'full_final_warning_threshold',
                   'full_first_warning_threshold', 'full_second_warning_threshold', 'log_quota',
                   'max_log_file_size', 'report_quota', 'roll_day',
                   'roll_schedule', 'roll_time', 'source_ip',
                   'status', 'upload', 'upload_delete_files',
                   'upload_destination', 'upload_format', 'upload_ssl_conn',
                   'uploaddir', 'uploadip', 'uploadpass',
                   'uploadport', 'uploadsched', 'uploadtime',
                   'uploadtype', 'uploaduser', 'uploadzip']

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
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def log_disk_setting(data, fos, check_mode=False):
    state = data.get('state', None)

    log_disk_setting_data = data['log_disk_setting']

    filtered_data = filter_log_disk_setting_data(log_disk_setting_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('log.disk', 'setting', filtered_data)
        current_data = fos.get('log.disk', 'setting', mkey=mkey)
        is_existed = current_data and current_data.get('http_status') == 200 \
            and isinstance(current_data.get('results'), list) \
            and len(current_data['results']) > 0

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == 'present' or state is True or state is None:
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
                    serialize(current_data['results']), serialize(copied_filtered_data))

                current_values = find_current_values(copied_filtered_data, current_data['results'])

                return False, not is_same, filtered_data, {"before": current_values, "after": copied_filtered_data}

            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data['results'][0]), serialize(copied_filtered_data))

                current_values = find_current_values(copied_filtered_data, current_data['results'][0])

                return False, not is_same, filtered_data, {"before": current_values, "after": copied_filtered_data}

            # record does not exist
            return False, True, filtered_data, diff

        if state == 'absent':
            if mkey is None:
                return False, False, filtered_data, {"before": current_data['results'][0], "after": ''}

            if is_existed:
                return False, True, filtered_data, {"before": current_data['results'][0], "after": ''}
            return False, False, filtered_data, {}

        return True, False, {'reason: ': 'Must provide state parameter'}, {}

    return fos.set('log.disk',
                   'setting',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_log_disk(data, fos, check_mode):
    fos.do_member_operation('log.disk', 'setting')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['log_disk_setting']:
        resp = log_disk_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('log_disk_setting'))
    if check_mode:
        return resp
    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "type": "dict",
    "children": {
        "uploaduser": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "uploaduser",
            "help": "User account in the uploading server.",
            "category": "unitary"
        },
        "uploadip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "uploadip",
            "help": "IP address of the log uploading server.",
            "category": "unitary"
        },
        "uploadtime": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "uploadtime",
            "help": "Time of scheduled upload.",
            "category": "unitary"
        },
        "diskfull": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "overwrite"
                },
                {
                    "value": "nolog"
                }
            ],
            "name": "diskfull",
            "help": "Policy to apply when disk is full.",
            "category": "unitary"
        },
        "roll_schedule": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "daily"
                },
                {
                    "value": "weekly"
                }
            ],
            "name": "roll-schedule",
            "help": "Frequency to check log file for rolling.",
            "category": "unitary"
        },
        "report_quota": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "integer",
            "name": "report-quota",
            "help": "Report quota.",
            "category": "unitary"
        },
        "roll_time": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "roll-time",
            "help": "Time to roll logs [hh:mm].",
            "category": "unitary"
        },
        "max_log_file_size": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "max-log-file-size",
            "help": "Max log file size in MB before rolling (may not be accurate all the time).",
            "category": "unitary"
        },
        "uploadtype": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "traffic"
                },
                {
                    "value": "event"
                },
                {
                    "value": "virus"
                },
                {
                    "value": "webfilter"
                },
                {
                    "value": "attack"
                },
                {
                    "value": "spamfilter"
                },
                {
                    "value": "dlp-archive"
                },
                {
                    "value": "dlp"
                },
                {
                    "value": "app-ctrl"
                }
            ],
            "name": "uploadtype",
            "help": "Types of log files that need to be uploaded.",
            "category": "unitary"
        },
        "source_ip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "source-ip",
            "help": "Source IP address of the disk log uploading.",
            "category": "unitary"
        },
        "status": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "status",
            "help": "Enable/disable local disk log.",
            "category": "unitary"
        },
        "drive_standby_time": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "drive-standby-time",
            "help": "Power management timeout(0-19800 sec)(0 disable).",
            "category": "unitary"
        },
        "upload_format": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "compact"
                },
                {
                    "value": "text"
                }
            ],
            "name": "upload-format",
            "help": "Upload compact/text logs.",
            "category": "unitary"
        },
        "full_final_warning_threshold": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "full-final-warning-threshold",
            "help": "Log full final warning threshold(3-100),the default is 95.",
            "category": "unitary"
        },
        "uploadpass": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "uploadpass",
            "help": "Password of the user account in the uploading server.",
            "category": "unitary"
        },
        "upload_ssl_conn": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "default"
                },
                {
                    "value": "high"
                },
                {
                    "value": "low"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "upload-ssl-conn",
            "help": "Enable/disable SSL communication when uploading.",
            "category": "unitary"
        },
        "upload_delete_files": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "upload-delete-files",
            "help": "Delete log files after uploading (default=enable).",
            "category": "unitary"
        },
        "log_quota": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "log-quota",
            "help": "Disk log quota.",
            "category": "unitary"
        },
        "uploaddir": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "uploaddir",
            "help": "Log file uploading remote directory.",
            "category": "unitary"
        },
        "full_first_warning_threshold": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "full-first-warning-threshold",
            "help": "Log full first warning threshold(1-98),the default is 75.",
            "category": "unitary"
        },
        "uploadport": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "uploadport",
            "help": "Port of the log uploading server.",
            "category": "unitary"
        },
        "upload": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "upload",
            "help": "Whether to upload the log file when rolling.",
            "category": "unitary"
        },
        "upload_destination": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "ftp-server"
                }
            ],
            "name": "upload-destination",
            "help": "Server type.",
            "category": "unitary"
        },
        "uploadsched": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "disable"
                },
                {
                    "value": "enable"
                }
            ],
            "name": "uploadsched",
            "help": "Scheduled upload (disable=upload when rolling).",
            "category": "unitary"
        },
        "uploadzip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "disable"
                },
                {
                    "value": "enable"
                }
            ],
            "name": "uploadzip",
            "help": "Compress upload logs.",
            "category": "unitary"
        },
        "roll_day": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "sunday"
                },
                {
                    "value": "monday"
                },
                {
                    "value": "tuesday"
                },
                {
                    "value": "wednesday"
                },
                {
                    "value": "thursday"
                },
                {
                    "value": "friday"
                },
                {
                    "value": "saturday"
                }
            ],
            "name": "roll-day",
            "help": "Days of week to roll logs.",
            "category": "unitary"
        },
        "full_second_warning_threshold": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "full-second-warning-threshold",
            "help": "Log full second warning threshold(2-99),the default is 90.",
            "category": "unitary"
        }
    },
    "name": "setting",
    "help": "Settings for local disk logging.",
    "category": "complex"
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = versioned_schema['mkey'] if 'mkey' in versioned_schema else None
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "log_disk_setting": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["log_disk_setting"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["log_disk_setting"]['options'][attribute_name]['required'] = True

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=True)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_custom_option('enable_log', module.params['enable_log'])
        else:
            connection.set_custom_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "log_disk_setting")
        is_error, has_changed, result, diff = fortiswitch_log_disk(module.params, fos, module.check_mode)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortiSwitch system and your playbook, see more details by specifying option -vvv")

    if not is_error:
        if versions_check_result and versions_check_result['matched'] is False:
            module.exit_json(changed=has_changed, version_check_warning=versions_check_result, meta=result, diff=diff)
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result['matched'] is False:
            module.fail_json(msg="Error in repo", version_check_warning=versions_check_result, meta=result)
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
