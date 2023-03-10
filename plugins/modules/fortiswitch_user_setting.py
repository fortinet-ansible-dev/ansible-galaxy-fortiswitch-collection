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
module: fortiswitch_user_setting
short_description: User authentication setting in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify user feature and setting category.
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

    user_setting:
        description:
            - User authentication setting.
        default: null
        type: dict
        suboptions:
            auth_blackout_time:
                description:
                    - Authentication blackout time (0 - 3600 sec).
                type: int
            auth_cert:
                description:
                    - HTTPS server cert for policy authentication.
                type: str
            auth_http_basic:
                description:
                    - Enable/disable use of HTTP BASIC for HTTP authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_invalid_max:
                description:
                    - Maximum number of invalid authentication attempts allowed before blackout (1 - 100).
                type: int
            auth_multi_group:
                description:
                    - Enable/disable retrival of all groups a user belongs to.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_ports:
                description:
                    - Authentication port table.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID.
                        type: int
                    port:
                        description:
                            - Non-standard port for firewall user authentication (1 - 65535).
                        type: int
                    type:
                        description:
                            - Service type.
                        type: str
                        choices:
                            - 'http'
                            - 'https'
                            - 'ftp'
                            - 'telnet'
            auth_secure_http:
                description:
                    - Enable/disable use of HTTPS for HTTP authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_timeout:
                description:
                    - Firewall user authentication timeout (1 - 480).
                type: int
            auth_timeout_type:
                description:
                    - Authenticated policy expiration behavior.
                type: str
                choices:
                    - 'idle-timeout'
                    - 'hard-timeout'
                    - 'new-session'
            auth_type:
                description:
                    - Allowed firewall policy authentication methods.
                type: str
                choices:
                    - 'http'
                    - 'https'
                    - 'ftp'
                    - 'telnet'
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
  - name: User authentication setting.
    fortiswitch_user_setting:
      user_setting:
        auth_blackout_time: "3"
        auth_cert: "<your_own_value>"
        auth_http_basic: "enable"
        auth_invalid_max: "6"
        auth_multi_group: "enable"
        auth_ports:
         -
            id:  "9"
            port: "10"
            type: "http"
        auth_secure_http: "enable"
        auth_timeout: "13"
        auth_timeout_type: "idle-timeout"
        auth_type: "http"

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


def filter_user_setting_data(json):
    option_list = ['auth_blackout_time', 'auth_cert', 'auth_http_basic',
                   'auth_invalid_max', 'auth_multi_group', 'auth_ports',
                   'auth_secure_http', 'auth_timeout', 'auth_timeout_type',
                   'auth_type']

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


def user_setting(data, fos):
    user_setting_data = data['user_setting']
    filtered_data = underscore_to_hyphen(filter_user_setting_data(user_setting_data))

    return fos.set('user',
                   'setting',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_user(data, fos):
    fos.do_member_operation('user', 'setting')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['user_setting']:
        resp = user_setting(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('user_setting'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "type": "dict",
    "children": {
        "auth_type": {
            "type": "string",
            "options": [
                {
                    "value": "http",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                {
                    "value": "https",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                {
                    "value": "ftp",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                {
                    "value": "telnet",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                }
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "auth_timeout": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "auth_multi_group": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                }
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "auth_http_basic": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                }
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "auth_cert": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "auth_blackout_time": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "auth_secure_http": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                }
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "auth_ports": {
            "elements": "dict",
            "type": "list",
            "children": {
                "type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "http",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        {
                            "value": "https",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        {
                            "value": "ftp",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        {
                            "value": "telnet",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "port": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                }
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "auth_timeout_type": {
            "type": "string",
            "options": [
                {
                    "value": "idle-timeout",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                {
                    "value": "hard-timeout",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                {
                    "value": "new-session",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                }
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "auth_invalid_max": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        }
    },
    "revisions": {
        "v7.0.3": True,
        "v7.0.2": True,
        "v7.0.1": True,
        "v7.0.0": True,
        "v7.0.6": True,
        "v7.0.5": True,
        "v7.0.4": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "user_setting": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["user_setting"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["user_setting"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "user_setting")
        is_error, has_changed, result, diff = fortiswitch_user(module.params, fos)
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
