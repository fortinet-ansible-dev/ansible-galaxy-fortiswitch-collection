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
module: fortiswitch_system_ntp
short_description: Ntp system info configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and ntp category.
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

    system_ntp:
        description:
            - Ntp system info configuration.
        default: null
        type: dict
        suboptions:
            allow_unsync_source:
                description:
                    - Enable/disable allowance of unsynchronized NTP server source.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            authentication:
                description:
                    - Enable/disable authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            key:
                description:
                    - Key for authentication.
                type: str
            key_id:
                description:
                    - Key ID for authentication.
                type: int
            key_type:
                description:
                    - Key type for authentication (MD5, SHA1).
                type: str
                choices:
                    - 'MD5'
                    - 'SHA1'
            log_time_adjustments:
                description:
                    - Enable/disable logging of NTP time adjustments.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ntpserver:
                description:
                    - NTP server.
                type: list
                elements: dict
                suboptions:
                    authentication:
                        description:
                            - Enable/disable MD5(NTPv3)/SHA1(NTPv4) authentication.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - Time server ID.
                        type: int
                    key:
                        description:
                            - Key for MD5(NTPv3)/SHA1(NTPv4) authentication.
                        type: str
                    key_id:
                        description:
                            - Key ID for authentication.
                        type: int
                    ntpv3:
                        description:
                            - Enable to use NTPv3 instead of NTPv4.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    server:
                        description:
                            - IP address/hostname of NTP server.
                        type: str
            ntpsync:
                description:
                    - Enable/disable synchronization with NTP server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            server_mode:
                description:
                    - On Enabling, your FortiSwitch relays NTP requests to its configured NTP server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            source_ip:
                description:
                    - Source IP for communications to NTP server.
                type: str
            source_ip6:
                description:
                    - Source IPv6 address for communication to the NTP server.
                type: str
            syncinterval:
                description:
                    - NTP synchronization interval (1 - 1440) min.
                type: int
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
  - name: Ntp system info configuration.
    fortiswitch_system_ntp:
      system_ntp:
        allow_unsync_source: "enable"
        authentication: "enable"
        key: "<your_own_value>"
        key_id: "6"
        key_type: "MD5"
        log_time_adjustments: "enable"
        ntpserver:
         -
            authentication: "enable"
            id:  "11"
            key: "<your_own_value>"
            key_id: "13"
            ntpv3: "enable"
            server: "192.168.100.40"
        ntpsync: "enable"
        server_mode: "enable"
        source_ip: "84.230.14.43"
        source_ip6: "<your_own_value>"
        syncinterval: "20"

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


def filter_system_ntp_data(json):
    option_list = ['allow_unsync_source', 'authentication', 'key',
                   'key_id', 'key_type', 'log_time_adjustments',
                   'ntpserver', 'ntpsync', 'server_mode',
                   'source_ip', 'source_ip6', 'syncinterval']

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


def system_ntp(data, fos):
    system_ntp_data = data['system_ntp']
    filtered_data = underscore_to_hyphen(filter_system_ntp_data(system_ntp_data))

    return fos.set('system',
                   'ntp',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):
    fos.do_member_operation('system', 'ntp')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_ntp']:
        resp = system_ntp(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_ntp'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "revisions": {
        "v7.0.0": True,
        "v7.0.1": True,
        "v7.0.2": True,
        "v7.0.3": True,
        "v7.0.4": True,
        "v7.0.5": True,
        "v7.0.6": True,
        "v7.2.1": True,
        "v7.2.2": True,
        "v7.2.3": True,
        "v7.2.4": True,
        "v7.2.5": True,
        "v7.4.0": True
    },
    "type": "dict",
    "children": {
        "key_type": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "MD5",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "SHA1",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "key_type",
            "help": "Key type for authentication (MD5,SHA1).",
            "category": "unitary"
        },
        "log_time_adjustments": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "log_time_adjustments",
            "help": "Enable/disable logging of NTP time adjustments.",
            "category": "unitary"
        },
        "server_mode": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "server_mode",
            "help": "On Enabling,your FortiSwitch relays NTP requests to its configured NTP server.",
            "category": "unitary"
        },
        "source_ip": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "name": "source_ip",
            "help": "Source IP for communications to NTP server.",
            "category": "unitary"
        },
        "allow_unsync_source": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "allow_unsync_source",
            "help": "Enable/disable allowance of unsynchronized NTP server source.",
            "category": "unitary"
        },
        "authentication": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "authentication",
            "help": "Enable/disable authentication.",
            "category": "unitary"
        },
        "source_ip6": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "name": "source_ip6",
            "help": "Source IPv6 address for communication to the NTP server.",
            "category": "unitary"
        },
        "key": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "name": "key",
            "help": "Key for authentication.",
            "category": "unitary"
        },
        "ntpsync": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    }
                }
            ],
            "name": "ntpsync",
            "help": "Enable/disable synchronization with NTP server.",
            "category": "unitary"
        },
        "syncinterval": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "syncinterval",
            "help": "NTP synchronization interval (1 - 1440) min.",
            "category": "unitary"
        },
        "ntpserver": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ntpv3": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "ntpv3",
                    "help": "Enable to use NTPv3 instead of NTPv4.",
                    "category": "unitary"
                },
                "server": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "server",
                    "help": "IP address/hostname of NTP server.",
                    "category": "unitary"
                },
                "authentication": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True,
                                "v7.2.2": True,
                                "v7.2.3": True,
                                "v7.2.4": True,
                                "v7.2.5": True,
                                "v7.4.0": True
                            }
                        }
                    ],
                    "name": "authentication",
                    "help": "Enable/disable MD5(NTPv3)/SHA1(NTPv4) authentication.",
                    "category": "unitary"
                },
                "key": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "string",
                    "name": "key",
                    "help": "Key for MD5(NTPv3)/SHA1(NTPv4) authentication.",
                    "category": "unitary"
                },
                "id": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "id",
                    "help": "Time server ID.",
                    "category": "unitary"
                },
                "key_id": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": True,
                        "v7.2.3": True,
                        "v7.2.4": True,
                        "v7.2.5": True,
                        "v7.4.0": True
                    },
                    "type": "integer",
                    "name": "key_id",
                    "help": "Key ID for authentication.",
                    "category": "unitary"
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "name": "ntpserver",
            "help": "NTP server.",
            "mkey": "id",
            "category": "table"
        },
        "key_id": {
            "revisions": {
                "v7.0.0": True,
                "v7.0.1": True,
                "v7.0.2": True,
                "v7.0.3": True,
                "v7.0.4": True,
                "v7.0.5": True,
                "v7.0.6": True,
                "v7.2.1": True,
                "v7.2.2": True,
                "v7.2.3": True,
                "v7.2.4": True,
                "v7.2.5": True,
                "v7.4.0": True
            },
            "type": "integer",
            "name": "key_id",
            "help": "Key ID for authentication.",
            "category": "unitary"
        }
    },
    "name": "ntp",
    "help": "Ntp system info configuration.",
    "category": "complex"
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
        "system_ntp": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_ntp"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_ntp"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_ntp")
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
