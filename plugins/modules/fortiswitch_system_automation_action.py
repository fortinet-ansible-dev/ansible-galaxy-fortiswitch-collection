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
module: fortiswitch_system_automation_action
short_description: Action for automation stitches in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and automation_action category.
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
    system_automation_action:
        description:
            - Action for automation stitches.
        default: null
        type: dict
        suboptions:
            accprofile:
                description:
                    - Access profile for CLI script action to access FortiSwitch features.
                type: str
            action_type:
                description:
                    - Action type.
                type: str
                choices:
                    - 'email'
                    - 'alert'
                    - 'cli_script'
                    - 'snmp_trap'
                    - 'webhook'
            alicloud_access_key_id:
                description:
                    - AliCloud AccessKey ID.
                type: str
            alicloud_access_key_secret:
                description:
                    - AliCloud AccessKey secret.
                type: str
            alicloud_account_id:
                description:
                    - AliCloud account ID.
                type: str
            alicloud_function:
                description:
                    - AliCloud function name.
                type: str
            alicloud_function_authorization:
                description:
                    - AliCloud function authorization type.
                type: str
                choices:
                    - 'anonymous'
                    - 'function'
            alicloud_function_domain:
                description:
                    - AliCloud function domain.
                type: str
            alicloud_region:
                description:
                    - AliCloud region.
                type: str
            alicloud_service:
                description:
                    - AliCloud service name.
                type: str
            alicloud_version:
                description:
                    - AliCloud version.
                type: str
            aws_api_id:
                description:
                    - AWS API Gateway ID.
                type: str
            aws_api_key:
                description:
                    - AWS API Gateway API key.
                type: str
            aws_api_path:
                description:
                    - AWS API Gateway path.
                type: str
            aws_api_stage:
                description:
                    - AWS API Gateway deployment stage name.
                type: str
            aws_domain:
                description:
                    - AWS domain.
                type: str
            aws_region:
                description:
                    - AWS region.
                type: str
            azure_api_key:
                description:
                    - Azure function API key.
                type: str
            azure_app:
                description:
                    - Azure function application name.
                type: str
            azure_domain:
                description:
                    - Azure function domain.
                type: str
            azure_function:
                description:
                    - Azure function name.
                type: str
            azure_function_authorization:
                description:
                    - Azure function authorization level.
                type: str
                choices:
                    - 'anonymous'
                    - 'function'
                    - 'admin'
            email_body:
                description:
                    - Email body.
                type: str
            email_from:
                description:
                    - Email sender name.
                type: str
            email_subject:
                description:
                    - Email subject.
                type: str
            email_to:
                description:
                    - Email addresses.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Email address.
                        type: str
            gcp_function:
                description:
                    - Google Cloud function name.
                type: str
            gcp_function_domain:
                description:
                    - Google Cloud function domain.
                type: str
            gcp_function_region:
                description:
                    - Google Cloud function region.
                type: str
            gcp_project:
                description:
                    - Google Cloud Platform project name.
                type: str
            headers:
                description:
                    - Request headers.
                type: list
                elements: dict
                suboptions:
                    header:
                        description:
                            - Request header.
                        type: str
            http_body:
                description:
                    - Request body (if necessary). Should be serialized json string.
                type: str
            method:
                description:
                    - Request method (POST, PUT, GET, PATCH or DELETE).
                type: str
                choices:
                    - 'post'
                    - 'put'
                    - 'get'
                    - 'patch'
                    - 'delete'
            minimum_interval:
                description:
                    - Limit execution to no more than once in this interval (in seconds).
                type: int
            name:
                description:
                    - Name.
                required: true
                type: str
            port:
                description:
                    - Protocol port.
                type: int
            protocol:
                description:
                    - Request protocol.
                type: str
                choices:
                    - 'http'
                    - 'https'
            script:
                description:
                    - CLI script.
                type: str
            snmp_trap:
                description:
                    - SNMP trap.
                type: str
                choices:
                    - 'cpu_high'
                    - 'mem_low'
                    - 'syslog_full'
                    - 'test_trap'
            uri:
                description:
                    - Request API URI.
                type: str
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
  - name: Action for automation stitches.
    fortiswitch_system_automation_action:
      state: "present"
      system_automation_action:
        accprofile: "<your_own_value> (source system.accprofile.name)"
        action_type: "email"
        alicloud_access_key_id: "<your_own_value>"
        alicloud_access_key_secret: "<your_own_value>"
        alicloud_account_id: "<your_own_value>"
        alicloud_function: "<your_own_value>"
        alicloud_function_authorization: "anonymous"
        alicloud_function_domain: "<your_own_value>"
        alicloud_region: "<your_own_value>"
        alicloud_service: "<your_own_value>"
        alicloud_version: "<your_own_value>"
        aws_api_id: "<your_own_value>"
        aws_api_key: "<your_own_value>"
        aws_api_path: "<your_own_value>"
        aws_api_stage: "<your_own_value>"
        aws_domain: "<your_own_value>"
        aws_region: "<your_own_value>"
        azure_api_key: "<your_own_value>"
        azure_app: "<your_own_value>"
        azure_domain: "<your_own_value>"
        azure_function: "<your_own_value>"
        azure_function_authorization: "anonymous"
        email_body: "<your_own_value>"
        email_from: "<your_own_value>"
        email_subject: "<your_own_value>"
        email_to:
         -
            name: "default_name_29"
        gcp_function: "<your_own_value>"
        gcp_function_domain: "<your_own_value>"
        gcp_function_region: "<your_own_value>"
        gcp_project: "<your_own_value>"
        headers:
         -
            header: "<your_own_value>"
        http_body: "<your_own_value>"
        method: "post"
        minimum_interval: "38"
        name: "default_name_39"
        port: "40"
        protocol: "http"
        script: "<your_own_value>"
        snmp_trap: "cpu-high"
        uri: "<your_own_value>"

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


def filter_system_automation_action_data(json):
    option_list = ['accprofile', 'action_type', 'alicloud_access_key_id',
                   'alicloud_access_key_secret', 'alicloud_account_id', 'alicloud_function',
                   'alicloud_function_authorization', 'alicloud_function_domain', 'alicloud_region',
                   'alicloud_service', 'alicloud_version', 'aws_api_id',
                   'aws_api_key', 'aws_api_path', 'aws_api_stage',
                   'aws_domain', 'aws_region', 'azure_api_key',
                   'azure_app', 'azure_domain', 'azure_function',
                   'azure_function_authorization', 'email_body', 'email_from',
                   'email_subject', 'email_to', 'gcp_function',
                   'gcp_function_domain', 'gcp_function_region', 'gcp_project',
                   'headers', 'http_body', 'method',
                   'minimum_interval', 'name', 'port',
                   'protocol', 'script', 'snmp_trap',
                   'uri']

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


def system_automation_action(data, fos):
    state = data['state']
    system_automation_action_data = data['system_automation_action']
    filtered_data = underscore_to_hyphen(filter_system_automation_action_data(system_automation_action_data))

    if state == "present" or state is True:
        return fos.set('system',
                       'automation-action',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system',
                          'automation-action',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):
    fos.do_member_operation('system', 'automation-action')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_automation_action']:
        resp = system_automation_action(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_automation_action'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "aws_api_key": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "aws_api_key",
            "help": "AWS API Gateway API key.",
            "category": "unitary"
        },
        "alicloud_account_id": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "alicloud_account_id",
            "help": "AliCloud account ID.",
            "category": "unitary"
        },
        "protocol": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "options": [
                {
                    "value": "http",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "https",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                }
            ],
            "name": "protocol",
            "help": "Request protocol.",
            "category": "unitary"
        },
        "alicloud_function": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "alicloud_function",
            "help": "AliCloud function name.",
            "category": "unitary"
        },
        "aws_domain": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "aws_domain",
            "help": "AWS domain.",
            "category": "unitary"
        },
        "aws_api_id": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "aws_api_id",
            "help": "AWS API Gateway ID.",
            "category": "unitary"
        },
        "email_to": {
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
                    "help": "Email address.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "name": "email_to",
            "help": "Email addresses.",
            "mkey": "name",
            "category": "table"
        },
        "azure_api_key": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "azure_api_key",
            "help": "Azure function API key.",
            "category": "unitary"
        },
        "port": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "integer",
            "name": "port",
            "help": "Protocol port.",
            "category": "unitary"
        },
        "minimum_interval": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "integer",
            "name": "minimum_interval",
            "help": "Limit execution to no more than once in this interval (in seconds).",
            "category": "unitary"
        },
        "gcp_function_domain": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "gcp_function_domain",
            "help": "Google Cloud function domain.",
            "category": "unitary"
        },
        "email_body": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "email_body",
            "help": "Email body.",
            "category": "unitary"
        },
        "http_body": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "http_body",
            "help": "Request body (if necessary). Should be serialized json string.",
            "category": "unitary"
        },
        "azure_domain": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "azure_domain",
            "help": "Azure function domain.",
            "category": "unitary"
        },
        "alicloud_version": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "alicloud_version",
            "help": "AliCloud version.",
            "category": "unitary"
        },
        "accprofile": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "accprofile",
            "help": "Access profile for CLI script action to access FortiSwitch features.",
            "category": "unitary"
        },
        "headers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "header": {
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    },
                    "type": "string",
                    "name": "header",
                    "help": "Request header.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "name": "headers",
            "help": "Request headers.",
            "mkey": "header",
            "category": "table"
        },
        "script": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "script",
            "help": "CLI script.",
            "category": "unitary"
        },
        "email_subject": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "email_subject",
            "help": "Email subject.",
            "category": "unitary"
        },
        "email_from": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "email_from",
            "help": "Email sender name.",
            "category": "unitary"
        },
        "aws_api_path": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "aws_api_path",
            "help": "AWS API Gateway path.",
            "category": "unitary"
        },
        "method": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "options": [
                {
                    "value": "post",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "put",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "get",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "patch",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "delete",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                }
            ],
            "name": "method",
            "help": "Request method (POST,PUT,GET,PATCH or DELETE).",
            "category": "unitary"
        },
        "action_type": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "options": [
                {
                    "value": "email",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "alert",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "cli_script",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "snmp_trap",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "webhook",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                }
            ],
            "name": "action_type",
            "help": "Action type.",
            "category": "unitary"
        },
        "alicloud_function_domain": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "alicloud_function_domain",
            "help": "AliCloud function domain.",
            "category": "unitary"
        },
        "azure_app": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "azure_app",
            "help": "Azure function application name.",
            "category": "unitary"
        },
        "gcp_function": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "gcp_function",
            "help": "Google Cloud function name.",
            "category": "unitary"
        },
        "alicloud_access_key_id": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "alicloud_access_key_id",
            "help": "AliCloud AccessKey ID.",
            "category": "unitary"
        },
        "gcp_project": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "gcp_project",
            "help": "Google Cloud Platform project name.",
            "category": "unitary"
        },
        "alicloud_access_key_secret": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "alicloud_access_key_secret",
            "help": "AliCloud AccessKey secret.",
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
        },
        "aws_region": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "aws_region",
            "help": "AWS region.",
            "category": "unitary"
        },
        "azure_function": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "azure_function",
            "help": "Azure function name.",
            "category": "unitary"
        },
        "aws_api_stage": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "aws_api_stage",
            "help": "AWS API Gateway deployment stage name.",
            "category": "unitary"
        },
        "alicloud_region": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "alicloud_region",
            "help": "AliCloud region.",
            "category": "unitary"
        },
        "uri": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "uri",
            "help": "Request API URI.",
            "category": "unitary"
        },
        "azure_function_authorization": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "options": [
                {
                    "value": "anonymous",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "function",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "admin",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                }
            ],
            "name": "azure_function_authorization",
            "help": "Azure function authorization level.",
            "category": "unitary"
        },
        "snmp_trap": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "options": [
                {
                    "value": "cpu_high",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "mem_low",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "syslog_full",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "test_trap",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                }
            ],
            "name": "snmp_trap",
            "help": "SNMP trap.",
            "category": "unitary"
        },
        "gcp_function_region": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "gcp_function_region",
            "help": "Google Cloud function region.",
            "category": "unitary"
        },
        "alicloud_service": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "name": "alicloud_service",
            "help": "AliCloud service name.",
            "category": "unitary"
        },
        "alicloud_function_authorization": {
            "revisions": {
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True
            },
            "type": "string",
            "options": [
                {
                    "value": "anonymous",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                },
                {
                    "value": "function",
                    "revisions": {
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True
                    }
                }
            ],
            "name": "alicloud_function_authorization",
            "help": "AliCloud function authorization type.",
            "category": "unitary"
        }
    },
    "revisions": {
        "v7.2.1": True,
        "v7.2.2": True,
        "v7.2.3": True
    },
    "name": "automation_action",
    "help": "Action for automation stitches.",
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
        "system_automation_action": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_automation_action"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_automation_action"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_automation_action")
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
