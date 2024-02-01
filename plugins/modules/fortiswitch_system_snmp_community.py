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
module: fortiswitch_system_snmp_community
short_description: SNMP community configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system_snmp feature and community category.
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
    system_snmp_community:
        description:
            - SNMP community configuration.
        default: null
        type: dict
        suboptions:
            events:
                description:
                    - Trap snmp events.
                type: str
                choices:
                    - 'cpu-high'
                    - 'mem-low'
                    - 'log-full'
                    - 'intf-ip'
                    - 'ent-conf-change'
                    - 'llv'
                    - 'l2mac'
                    - 'sensor-fault'
                    - 'sensor-alarm'
                    - 'fan-detect'
                    - 'psu-status'
                    - 'ip-conflict'
                    - 'tkmem-hb-oo-sync'
            hosts:
                description:
                    - Allow hosts configuration.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Host entry id.
                        type: int
                    interface:
                        description:
                            - Allow interface name.
                        type: str
                    ip:
                        description:
                            - Allow host ip address and netmask.
                        type: str
                    source_ip:
                        description:
                            - Source ip for snmp trap.
                        type: str
            hosts6:
                description:
                    - Allow hosts configuration for IPv6.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Host6 entry id.
                        type: int
                    interface:
                        description:
                            - Allow interface name.
                        type: str
                    ipv6:
                        description:
                            - Allow host ipv6 address.
                        type: str
                    source_ipv6:
                        description:
                            - Source ipv6 for snmp trap.
                        type: str
            id:
                description:
                    - Community id.
                required: true
                type: int
            name:
                description:
                    - Community name.
                type: str
            query_v1_port:
                description:
                    - SNMP v1 query port.
                type: int
            query_v1_status:
                description:
                    - Enable/disable snmp v1 query.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            query_v2c_port:
                description:
                    - SNMP v2c query port.
                type: int
            query_v2c_status:
                description:
                    - Enable/disable snmp v2c query.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            status:
                description:
                    - Enable/disable this commuity.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trap_v1_lport:
                description:
                    - SNMP v1 trap local port.
                type: int
            trap_v1_rport:
                description:
                    - SNMP v1 trap remote port.
                type: int
            trap_v1_status:
                description:
                    - Enable/disable snmp v1 trap.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trap_v2c_lport:
                description:
                    - SNMP v2c trap local port.
                type: int
            trap_v2c_rport:
                description:
                    - SNMP v2c trap remote port.
                type: int
            trap_v2c_status:
                description:
                    - Enable/disable snmp v2c trap.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
'''

EXAMPLES = '''
- name: SNMP community configuration.
  fortinet.fortiswitch.fortiswitch_system_snmp_community:
      state: "present"
      system_snmp_community:
          events: "cpu-high"
          hosts:
              -
                  id: "5"
                  interface: "<your_own_value> (source system.interface.name)"
                  ip: "<your_own_value>"
                  source_ip: "<your_own_value>"
          hosts6:
              -
                  id: "10"
                  interface: "<your_own_value> (source system.interface.name)"
                  ipv6: "<your_own_value>"
                  source_ipv6: "<your_own_value>"
          id: "14"
          name: "default_name_15"
          query_v1_port: "16"
          query_v1_status: "enable"
          query_v2c_port: "18"
          query_v2c_status: "enable"
          status: "enable"
          trap_v1_lport: "21"
          trap_v1_rport: "22"
          trap_v1_status: "enable"
          trap_v2c_lport: "24"
          trap_v2c_rport: "25"
          trap_v2c_status: "enable"
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


def filter_system_snmp_community_data(json):
    option_list = ['events', 'hosts', 'hosts6',
                   'id', 'name', 'query_v1_port',
                   'query_v1_status', 'query_v2c_port', 'query_v2c_status',
                   'status', 'trap_v1_lport', 'trap_v1_rport',
                   'trap_v1_status', 'trap_v2c_lport', 'trap_v2c_rport',
                   'trap_v2c_status']

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


def system_snmp_community(data, fos, check_mode=False):
    state = data['state']
    system_snmp_community_data = data['system_snmp_community']
    filtered_data = underscore_to_hyphen(filter_system_snmp_community_data(system_snmp_community_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('system.snmp', 'community', filtered_data)
        current_data = fos.get('system.snmp', 'community', mkey=mkey)
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
        return fos.set('system.snmp',
                       'community',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system.snmp',
                          'community',
                          mkey=filtered_data['id'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system_snmp(data, fos, check_mode):
    fos.do_member_operation('system.snmp', 'community')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_snmp_community']:
        resp = system_snmp_community(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_snmp_community'))
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
            "help": "Enable/disable this commuity.",
            "category": "unitary"
        },
        "trap_v2c_lport": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "trap-v2c-lport",
            "help": "SNMP v2c trap local port.",
            "category": "unitary"
        },
        "hosts6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "source_ipv6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "source-ipv6",
                    "help": "Source ipv6 for snmp trap.",
                    "category": "unitary"
                },
                "interface": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "interface",
                    "help": "Allow interface name.",
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
                    "help": "Host6 entry id.",
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
                    "help": "Allow host ipv6 address.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "hosts6",
            "help": "Allow hosts configuration for IPv6.",
            "mkey": "id",
            "category": "table"
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
            "help": "Community name.",
            "category": "unitary"
        },
        "query_v1_port": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "query-v1-port",
            "help": "SNMP v1 query port.",
            "category": "unitary"
        },
        "query_v2c_port": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "query-v2c-port",
            "help": "SNMP v2c query port.",
            "category": "unitary"
        },
        "query_v2c_status": {
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
            "name": "query-v2c-status",
            "help": "Enable/disable snmp v2c query.",
            "category": "unitary"
        },
        "trap_v1_rport": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "trap-v1-rport",
            "help": "SNMP v1 trap remote port.",
            "category": "unitary"
        },
        "query_v1_status": {
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
            "name": "query-v1-status",
            "help": "Enable/disable snmp v1 query.",
            "category": "unitary"
        },
        "trap_v2c_status": {
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
            "name": "trap-v2c-status",
            "help": "Enable/disable snmp v2c trap.",
            "category": "unitary"
        },
        "hosts": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "interface",
                    "help": "Allow interface name.",
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
                    "help": "Allow host ip address and netmask.",
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
                    "help": "Source ip for snmp trap.",
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
                    "help": "Host entry id.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "hosts",
            "help": "Allow hosts configuration.",
            "mkey": "id",
            "category": "table"
        },
        "trap_v1_status": {
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
            "name": "trap-v1-status",
            "help": "Enable/disable snmp v1 trap.",
            "category": "unitary"
        },
        "events": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "cpu-high"
                },
                {
                    "value": "mem-low"
                },
                {
                    "value": "log-full"
                },
                {
                    "value": "intf-ip"
                },
                {
                    "value": "ent-conf-change"
                },
                {
                    "value": "llv",
                    "v_range": [
                        [
                            "v7.0.2",
                            ""
                        ]
                    ]
                },
                {
                    "value": "l2mac",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                },
                {
                    "value": "sensor-fault",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                },
                {
                    "value": "sensor-alarm",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                },
                {
                    "value": "fan-detect",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                },
                {
                    "value": "psu-status",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                },
                {
                    "value": "ip-conflict",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                },
                {
                    "value": "tkmem-hb-oo-sync",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                }
            ],
            "name": "events",
            "help": "Trap snmp events.",
            "category": "unitary"
        },
        "trap_v2c_rport": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "trap-v2c-rport",
            "help": "SNMP v2c trap remote port.",
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
            "help": "Community id.",
            "category": "unitary"
        },
        "trap_v1_lport": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "trap-v1-lport",
            "help": "SNMP v1 trap local port.",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "name": "community",
    "help": "SNMP community configuration.",
    "mkey": "id",
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
        "system_snmp_community": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_snmp_community"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_snmp_community"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_snmp_community")
        is_error, has_changed, result, diff = fortiswitch_system_snmp(module.params, fos, module.check_mode)
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
