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
module: fortiswitch_system_fortiguard
short_description: Configure FortiGuard services in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and fortiguard category.
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

    system_fortiguard:
        description:
            - Configure FortiGuard services.
        default: null
        type: dict
        suboptions:
            analysis_service:
                description:
                    - Enable or disable the analysis service.
                type: str
                choices:
                    - enable
                    - disable
            antispam_cache:
                description:
                    - Enable/disable the cache.
                type: str
                choices:
                    - enable
                    - disable
            antispam_cache_mpercent:
                description:
                    - The maximum percent of memory the cache is allowed to use (1-15%).
                type: int
            antispam_cache_ttl:
                description:
                    - The time-to-live for cache entries in seconds (300-86400).
                type: int
            antispam_expiration:
                description:
                    - When license will expire.
                type: int
            antispam_force_off:
                description:
                    - Forcibly disable the service.
                type: str
                choices:
                    - enable
                    - disable
            antispam_license:
                description:
                    - License type.
                type: int
            antispam_score_threshold:
                description:
                    - Antispam score threshold [50,100].
                type: int
            antispam_timeout:
                description:
                    - Query time out (1-30 seconds).
                type: int
            avquery_cache:
                description:
                    - Enable/disable the cache.
                type: str
                choices:
                    - enable
                    - disable
            avquery_cache_mpercent:
                description:
                    - The maximum percent of memory the cache is allowed to use (1-15%).
                type: int
            avquery_cache_ttl:
                description:
                    - The time-to-live for cache entries in seconds (300-86400).
                type: int
            avquery_expiration:
                description:
                    - When license will expire.
                type: int
            avquery_force_off:
                description:
                    - Forcibly disable the service.
                type: str
                choices:
                    - enable
                    - disable
            avquery_license:
                description:
                    - License type.
                type: int
            avquery_timeout:
                description:
                    - Query time out (1-30 seconds).
                type: int
            client_override_ip:
                description:
                    - Client override IP address.
                type: str
            client_override_status:
                description:
                    - Enable or disable the client override IP.
                type: str
                choices:
                    - enable
                    - disable
            hostname:
                description:
                    - Hostname or IP of the FortiGuard server.
                type: str
            load_balance_servers:
                description:
                    - Number of servers to alternate between as first Fortiguard option.
                type: int
            port:
                description:
                    - Port used to communicate with the FortiGuard servers.
                type: str
                choices:
                    - 53
                    - 8888
            service_account_id:
                description:
                    - Service account id.
                type: str
            srv_ovrd:
                description:
                    - Enable or disable the server override list.
                type: str
                choices:
                    - enable
                    - disable
            srv_ovrd_list:
                description:
                    - Configure the server override list.
                type: list
                suboptions:
                    addr_type:
                        description:
                            - Type of address.
                        type: str
                        choices:
                            - ipv4
                            - ipv6
                    ip:
                        description:
                            - Override server IP address.
                        type: str
                    ip6:
                        description:
                            - Override server IP6 address.
                        type: str
            webfilter_cache:
                description:
                    - Enable/disable the cache.
                type: str
                choices:
                    - enable
                    - disable
            webfilter_cache_ttl:
                description:
                    - The time-to-live for cache entries in seconds (300-86400).
                type: int
            webfilter_expiration:
                description:
                    - When license will expire.
                type: int
            webfilter_force_off:
                description:
                    - Forcibly disable the service.
                type: str
                choices:
                    - enable
                    - disable
            webfilter_license:
                description:
                    - License type.
                type: int
            webfilter_timeout:
                description:
                    - Query time out (1-30 seconds).
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
  - name: Configure FortiGuard services.
    fortiswitch_system_fortiguard:
      state: "present"
      system_fortiguard:
        analysis_service: "enable"
        antispam_cache: "enable"
        antispam_cache_mpercent: "5"
        antispam_cache_ttl: "6"
        antispam_expiration: "7"
        antispam_force_off: "enable"
        antispam_license: "9"
        antispam_score_threshold: "10"
        antispam_timeout: "11"
        avquery_cache: "enable"
        avquery_cache_mpercent: "13"
        avquery_cache_ttl: "14"
        avquery_expiration: "15"
        avquery_force_off: "enable"
        avquery_license: "17"
        avquery_timeout: "18"
        client_override_ip: "<your_own_value>"
        client_override_status: "enable"
        hostname: "myhostname"
        load_balance_servers: "22"
        port: "53"
        service_account_id: "<your_own_value>"
        srv_ovrd: "enable"
        srv_ovrd_list:
         -
            addr_type: "ipv4"
            ip: "<your_own_value>"
            ip6: "<your_own_value>"
        webfilter_cache: "enable"
        webfilter_cache_ttl: "31"
        webfilter_expiration: "32"
        webfilter_force_off: "enable"
        webfilter_license: "34"
        webfilter_timeout: "35"

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


def filter_system_fortiguard_data(json):
    option_list = ['analysis_service', 'antispam_cache', 'antispam_cache_mpercent',
                   'antispam_cache_ttl', 'antispam_expiration', 'antispam_force_off',
                   'antispam_license', 'antispam_score_threshold', 'antispam_timeout',
                   'avquery_cache', 'avquery_cache_mpercent', 'avquery_cache_ttl',
                   'avquery_expiration', 'avquery_force_off', 'avquery_license',
                   'avquery_timeout', 'client_override_ip', 'client_override_status',
                   'hostname', 'load_balance_servers', 'port',
                   'service_account_id', 'srv_ovrd', 'srv_ovrd_list',
                   'webfilter_cache', 'webfilter_cache_ttl', 'webfilter_expiration',
                   'webfilter_force_off', 'webfilter_license', 'webfilter_timeout']
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


def system_fortiguard(data, fos):
    system_fortiguard_data = data['system_fortiguard']
    filtered_data = underscore_to_hyphen(filter_system_fortiguard_data(system_fortiguard_data))

    return fos.set('system',
                   'fortiguard',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):

    fos.do_member_operation('system_fortiguard')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_fortiguard']:
        resp = system_fortiguard(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_fortiguard'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp


versioned_schema = {
    "type": "dict",
    "children": {
        "avquery_cache_mpercent": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "srv_ovrd": {
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
        "webfilter_license": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "antispam_timeout": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "antispam_cache_mpercent": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "antispam_cache": {
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
        "srv_ovrd_list": {
            "type": "list",
            "children": {
                "ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "addr_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ipv4",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "ipv6",
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
        },
        "webfilter_force_off": {
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
        "port": {
            "type": "string",
            "options": [
                {
                    "value": "53",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "8888",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "webfilter_expiration": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "service_account_id": {
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
        "antispam_expiration": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "avquery_force_off": {
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
        "webfilter_cache": {
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
        "webfilter_cache_ttl": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "antispam_license": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "webfilter_timeout": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "antispam_cache_ttl": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "avquery_cache_ttl": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "antispam_force_off": {
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
        "avquery_cache": {
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
        "client_override_status": {
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
        "avquery_timeout": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "analysis_service": {
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
        "antispam_score_threshold": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "avquery_license": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "avquery_expiration": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "client_override_ip": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "load_balance_servers": {
            "type": "integer",
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
        "system_fortiguard": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_fortiguard"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_fortiguard"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_fortiguard")

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
