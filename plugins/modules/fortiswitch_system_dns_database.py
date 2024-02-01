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
module: fortiswitch_system_dns_database
short_description: Dns-database in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and dns_database category.
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
    - ansible>=2.14
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
    system_dns_database:
        description:
            - Dns-database.
        default: null
        type: dict
        suboptions:
            allow_transfer:
                description:
                    - Dns zone transfer ip address list.
                type: str
            authoritative:
                description:
                    - Authoritative zone.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            contact:
                description:
                    - Email address of the administrator for this zone
                type: str
            dns_entry:
                description:
                    - Dns entry.
                type: list
                elements: dict
                suboptions:
                    canonical_name:
                        description:
                            - Canonical name.
                        type: str
                    hostname:
                        description:
                            - Hostname.
                        type: str
                    id:
                        description:
                            - Dns entry id.
                        type: int
                    ip:
                        description:
                            - IPv4 address.
                        type: str
                    ipv6:
                        description:
                            - IPv6 address.
                        type: str
                    preference:
                        description:
                            - 0 for the highest preference, range 0 to 65535.
                        type: int
                    status:
                        description:
                            - Resource record status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ttl:
                        description:
                            - Time-to-live value in units of seconds for this entry, range 0 to 2147483647.
                        type: int
                    type:
                        description:
                            - Resource record type.
                        type: str
                        choices:
                            - 'A'
                            - 'NS'
                            - 'CNAME'
                            - 'MX'
                            - 'AAAA'
                            - 'PTR'
                            - 'PTR_V6'
            domain:
                description:
                    - Domain name.
                type: str
            forwarder:
                description:
                    - Dns zone forwarder ip address list.
                type: str
            ip_master:
                description:
                    - IP address of master DNS server to import entries of this zone.
                type: str
            name:
                description:
                    - Zone name.
                required: true
                type: str
            primary_name:
                description:
                    - Domain name of the default DNS server for this zone.
                type: str
            source_ip:
                description:
                    - Source IP for forwarding to DNS server.
                type: str
            status:
                description:
                    - Dns zone status.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ttl:
                description:
                    - Default time-to-live value in units of seconds for the entries of this zone, range 0 to 2147483647.
                type: int
            type:
                description:
                    - Zone type ("master" to manage entries directly, "slave" to import entries from outside).
                type: str
                choices:
                    - 'master'
                    - 'slave'
            view:
                description:
                    - Zone view ("public" to server public clients, "shadow" to serve internal clients).
                type: str
                choices:
                    - 'shadow'
                    - 'public'
'''

EXAMPLES = '''
- name: Dns-database.
  fortinet.fortiswitch.fortiswitch_system_dns_database:
      state: "present"
      system_dns_database:
          allow_transfer: "<your_own_value>"
          authoritative: "enable"
          contact: "<your_own_value>"
          dns_entry:
              -
                  canonical_name: "<your_own_value>"
                  hostname: "myhostname"
                  id: "9"
                  ip: "<your_own_value>"
                  ipv6: "<your_own_value>"
                  preference: "12"
                  status: "enable"
                  ttl: "14"
                  type: "A"
          domain: "<your_own_value>"
          forwarder: "<your_own_value>"
          ip_master: "<your_own_value>"
          name: "default_name_19"
          primary_name: "<your_own_value>"
          source_ip: "<your_own_value>"
          status: "enable"
          ttl: "23"
          type: "master"
          view: "shadow"
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


def filter_system_dns_database_data(json):
    option_list = ['allow_transfer', 'authoritative', 'contact',
                   'dns_entry', 'domain', 'forwarder',
                   'ip_master', 'name', 'primary_name',
                   'source_ip', 'status', 'ttl',
                   'type', 'view']

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


def system_dns_database(data, fos, check_mode=False):
    state = data['state']
    system_dns_database_data = data['system_dns_database']
    filtered_data = underscore_to_hyphen(filter_system_dns_database_data(system_dns_database_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('system', 'dns-database', filtered_data)
        current_data = fos.get('system', 'dns-database', mkey=mkey)
        is_existed = current_data and current_data.get('http_status') == 200 \
            and isinstance(current_data.get('results'), list) \
            and len(current_data['results']) > 0

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == 'present' or state is True:
            if mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data['results'][0]), serialize(filtered_data))
                return False, not is_same, filtered_data, {"before": current_data['results'][0], "after": filtered_data}

            # record does not exist
            return False, True, filtered_data, diff

        if state == 'absent':
            if mkey is None:
                return False, False, filtered_data, {"before": current_data['results'][0], "after": ''}

            if is_existed:
                return False, True, filtered_data, {"before": current_data['results'][0], "after": ''}
            return False, False, filtered_data, {}

        return True, False, {'reason: ': 'Must provide state parameter'}, {}

    if state == "present" or state is True:
        return fos.set('system',
                       'dns-database',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system',
                          'dns-database',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos, check_mode):
    fos.do_member_operation('system', 'dns-database')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_dns_database']:
        resp = system_dns_database(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_dns_database'))
    if check_mode:
        return resp
    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
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
            "help": "Dns zone status.",
            "category": "unitary"
        },
        "domain": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "domain",
            "help": "Domain name.",
            "category": "unitary"
        },
        "name": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "name",
            "help": "Zone name.",
            "category": "unitary"
        },
        "authoritative": {
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
            "name": "authoritative",
            "help": "Authoritative zone.",
            "category": "unitary"
        },
        "primary_name": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "primary-name",
            "help": "Domain name of the default DNS server for this zone.",
            "category": "unitary"
        },
        "ip_master": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "ip-master",
            "help": "IP address of master DNS server to import entries of this zone.",
            "category": "unitary"
        },
        "dns_entry": {
            "type": "list",
            "elements": "dict",
            "children": {
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
                    "help": "Resource record status.",
                    "category": "unitary"
                },
                "hostname": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "hostname",
                    "help": "Hostname.",
                    "category": "unitary"
                },
                "ip": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "ip",
                    "help": "IPv4 address.",
                    "category": "unitary"
                },
                "ipv6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "ipv6",
                    "help": "IPv6 address.",
                    "category": "unitary"
                },
                "canonical_name": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "canonical-name",
                    "help": "Canonical name.",
                    "category": "unitary"
                },
                "preference": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "preference",
                    "help": "0 for the highest preference,range 0 to 65535.",
                    "category": "unitary"
                },
                "ttl": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ttl",
                    "help": "Time-to-live value in units of seconds for this entry,range 0 to 2147483647.",
                    "category": "unitary"
                },
                "type": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "A"
                        },
                        {
                            "value": "NS"
                        },
                        {
                            "value": "CNAME"
                        },
                        {
                            "value": "MX"
                        },
                        {
                            "value": "AAAA"
                        },
                        {
                            "value": "PTR"
                        },
                        {
                            "value": "PTR_V6"
                        }
                    ],
                    "name": "type",
                    "help": "Resource record type.",
                    "category": "unitary"
                },
                "id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "id",
                    "help": "Dns entry id.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "dns-entry",
            "help": "Dns entry.",
            "mkey": "id",
            "category": "table"
        },
        "contact": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "contact",
            "help": "Email address of the administrator for this zone",
            "category": "unitary"
        },
        "ttl": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "ttl",
            "help": "Default time-to-live value in units of seconds for the entries of this zone,range 0 to 2147483647.",
            "category": "unitary"
        },
        "forwarder": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "forwarder",
            "help": "Dns zone forwarder ip address list.",
            "category": "unitary"
        },
        "allow_transfer": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "allow-transfer",
            "help": "Dns zone transfer ip address list.",
            "category": "unitary"
        },
        "type": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "master"
                },
                {
                    "value": "slave"
                }
            ],
            "name": "type",
            "help": "Zone type ('master' to manage entries directly,'slave' to import entries from outside).",
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
            "help": "Source IP for forwarding to DNS server.",
            "category": "unitary"
        },
        "view": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "shadow"
                },
                {
                    "value": "public"
                }
            ],
            "name": "view",
            "help": "Zone view ('public' to server public clients,'shadow' to serve internal clients).",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "name": "dns-database",
    "help": "Dns-database.",
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
        "system_dns_database": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_dns_database"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_dns_database"]['options'][attribute_name]['required'] = True

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
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_dns_database")
        is_error, has_changed, result, diff = fortiswitch_system(module.params, fos, module.check_mode)
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
