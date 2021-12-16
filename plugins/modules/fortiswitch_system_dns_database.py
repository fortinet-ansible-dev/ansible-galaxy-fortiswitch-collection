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
module: fortiswitch_system_dns_database
short_description: Dns-database in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and dns_database category.
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
                    - enable
                    - disable
            contact:
                description:
                    - Email address of the administrator for this zone  you can specify only the username (e.g. admin)or full email address (e.g. admin
                      .ca@test.com)   when using simple username, the domain of the email will be this zone.
                type: str
            dns_entry:
                description:
                    - Dns entry.
                type: list
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
                        required: true
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
                            - enable
                            - disable
                    ttl:
                        description:
                            - Time-to-live value in units of seconds for this entry, range 0 to 2147483647.
                        type: int
                    type:
                        description:
                            - Resource record type.
                        type: str
                        choices:
                            - A
                            - NS
                            - CNAME
                            - MX
                            - AAAA
                            - PTR
                            - PTR_V6
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
                    - enable
                    - disable
            ttl:
                description:
                    - Default time-to-live value in units of seconds for the entries of this zone, range 0 to 2147483647.
                type: int
            type:
                description:
                    - Zone type ("master" to manage entries directly, "slave" to import entries from outside).
                type: str
                choices:
                    - master
                    - slave
            view:
                description:
                    - Zone view ("public" to server public clients, "shadow" to serve internal clients).
                type: str
                choices:
                    - shadow
                    - public
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
  - name: Dns-database.
    fortiswitch_system_dns_database:
      state: "present"
      system_dns_database:
        allow_transfer: "<your_own_value>"
        authoritative: "enable"
        contact: "<your_own_value>"
        dns_entry:
         -
            canonical_name: "<your_own_value>"
            hostname: "myhostname"
            id:  "9"
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
        source_ip: "84.230.14.43"
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


def filter_system_dns_database_data(json):
    option_list = ['allow_transfer', 'authoritative', 'contact',
                   'dns_entry', 'domain', 'forwarder',
                   'ip_master', 'name', 'primary_name',
                   'source_ip', 'status', 'ttl',
                   'type', 'view']
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


def system_dns_database(data, fos):

    state = data['state']

    system_dns_database_data = data['system_dns_database']
    filtered_data = underscore_to_hyphen(filter_system_dns_database_data(system_dns_database_data))

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


def fortiswitch_system(data, fos):

    fos.do_member_operation('system_dns_database')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_dns_database']:
        resp = system_dns_database(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_dns_database'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "status": {
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
        "ip_master": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "domain": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "authoritative": {
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
        "source_ip": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "contact": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "primary_name": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "dns_entry": {
            "type": "list",
            "children": {
                "status": {
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
                "ttl": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "hostname": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "canonical_name": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "preference": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ipv6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "A",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "NS",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "CNAME",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "MX",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "AAAA",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "PTR",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "PTR_V6",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        },
        "ttl": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "forwarder": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "type": {
            "type": "string",
            "options": [
                {
                    "value": "master",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "slave",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "allow_transfer": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "view": {
            "type": "string",
            "options": [
                {
                    "value": "shadow",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "public",
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
    mkeyname = 'name'
    fields = {
        "enable_log": {"required": False, "type": bool},
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
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_dns_database"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_dns_database"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_dns_database")

        is_error, has_changed, result = fortiswitch_system(module.params, fos)

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
