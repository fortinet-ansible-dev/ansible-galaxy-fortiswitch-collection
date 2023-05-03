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
module: fortiswitch_system_automation_trigger
short_description: Trigger for automation stitches in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and automation_trigger category.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    system_automation_trigger:
        description:
            - Trigger for automation stitches.
        default: null
        type: dict
        suboptions:
            event_type:
                description:
                    - Event type.
                type: str
                choices:
                    - 'config_change'
                    - 'event_log'
                    - 'reboot'
            fields:
                description:
                    - Customized trigger field settings.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Entry ID.
                        type: int
                    name:
                        description:
                            - Name.
                        type: str
                    value:
                        description:
                            - Value.
                        type: str
            logid:
                description:
                    - Log ID to trigger event.
                type: str
            name:
                description:
                    - Name.
                required: true
                type: str
            trigger_day:
                description:
                    - Day within a month to trigger.
                type: int
            trigger_frequency:
                description:
                    - Scheduled trigger frequency .
                type: str
                choices:
                    - 'hourly'
                    - 'daily'
                    - 'weekly'
                    - 'monthly'
            trigger_hour:
                description:
                    - Hour of the day on which to trigger (0 - 23).
                type: int
            trigger_minute:
                description:
                    - Minute of the hour on which to trigger (0 - 59).
                type: int
            trigger_type:
                description:
                    - Trigger type.
                type: str
                choices:
                    - 'event_based'
                    - 'scheduled'
            trigger_weekday:
                description:
                    - Day of week for trigger.
                type: str
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
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
  - name: Trigger for automation stitches.
    fortiswitch_system_automation_trigger:
      state: "present"
      system_automation_trigger:
        event_type: "config-change"
        fields:
         -
            id:  "5"
            name: "default_name_6"
            value: "<your_own_value>"
        logid: "<your_own_value>"
        name: "default_name_9"
        trigger_day: "10"
        trigger_frequency: "hourly"
        trigger_hour: "12"
        trigger_minute: "13"
        trigger_type: "event-based"
        trigger_weekday: "sunday"

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


def filter_system_automation_trigger_data(json):
    option_list = ['event_type', 'fields', 'logid',
                   'name', 'trigger_day', 'trigger_frequency',
                   'trigger_hour', 'trigger_minute', 'trigger_type',
                   'trigger_weekday']

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


def system_automation_trigger(data, fos):
    state = data['state']
    system_automation_trigger_data = data['system_automation_trigger']
    filtered_data = underscore_to_hyphen(filter_system_automation_trigger_data(system_automation_trigger_data))

    if state == "present" or state is True:
        return fos.set('system',
                       'automation-trigger',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system',
                          'automation-trigger',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):
    fos.do_member_operation('system', 'automation-trigger')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_automation_trigger']:
        resp = system_automation_trigger(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_automation_trigger'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "name",
            "help": "Name.",
            "category": "unitary"
        },
        "trigger_minute": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "integer",
            "name": "trigger_minute",
            "help": "Minute of the hour on which to trigger (0 - 59,default = 0).",
            "category": "unitary"
        },
        "fields": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    },
                    "type": "integer",
                    "name": "id",
                    "help": "Entry ID.",
                    "category": "unitary"
                },
                "value": {
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    },
                    "type": "string",
                    "name": "value",
                    "help": "Value.",
                    "category": "unitary"
                },
                "name": {
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    },
                    "type": "string",
                    "name": "name",
                    "help": "Name.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "name": "fields",
            "help": "Customized trigger field settings.",
            "mkey": "id",
            "category": "table"
        },
        "logid": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "logid",
            "help": "Log ID to trigger event.",
            "category": "unitary"
        },
        "trigger_hour": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "integer",
            "name": "trigger_hour",
            "help": "Hour of the day on which to trigger (0 - 23,default = 1).",
            "category": "unitary"
        },
        "trigger_type": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "options": [
                {
                    "value": "event_based",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "scheduled",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                }
            ],
            "name": "trigger_type",
            "help": "Trigger type.",
            "category": "unitary"
        },
        "event_type": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "options": [
                {
                    "value": "config_change",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "event_log",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "reboot",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                }
            ],
            "name": "event_type",
            "help": "Event type.",
            "category": "unitary"
        },
        "trigger_frequency": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "options": [
                {
                    "value": "hourly",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "daily",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "weekly",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "monthly",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                }
            ],
            "name": "trigger_frequency",
            "help": "Scheduled trigger frequency (default = daily).",
            "category": "unitary"
        },
        "trigger_weekday": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "options": [
                {
                    "value": "sunday",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "monday",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "tuesday",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "wednesday",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "thursday",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "friday",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "saturday",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                }
            ],
            "name": "trigger_weekday",
            "help": "Day of week for trigger.",
            "category": "unitary"
        },
        "trigger_day": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "integer",
            "name": "trigger_day",
            "help": "Day within a month to trigger.",
            "category": "unitary"
        }
    },
    "revisions": {
        "v7.2.1": True,
        "v7.2.2": True,
        "v7.2.3": True
    },
    "name": "automation_trigger",
    "help": "Trigger for automation stitches.",
    "mkey": "name",
    "category": "table"
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    # mkeyname = None
    mkeyname = versioned_schema['mkey'] if 'mkey' in versioned_schema else None
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "system_automation_trigger": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_automation_trigger"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_automation_trigger"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_automation_trigger")
        is_error, has_changed, result, diff = fortiswitch_system(module.params, fos)
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
