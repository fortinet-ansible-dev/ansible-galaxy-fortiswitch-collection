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
module: fortiswitch_switch_acl_802_1x
short_description: 802-1X Radius Dynamic Ingress Policy configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch_acl feature and 802_1x category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v7.0.0
version_added: "1.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
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
    switch_acl_802_1x:
        description:
            - 802-1X Radius Dynamic Ingress Policy configuration.
        default: null
        type: dict
        suboptions:
            access_list_entry:
                description:
                    - Access Control List Entry configuration.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Actions for the policy.
                        type: dict
                        suboptions:
                            count:
                                description:
                                    - Count enable/disable action.
                                type: str
                                choices:
                                    - enable
                                    - disable
                            drop:
                                description:
                                    - Drop enable/disable action.
                                type: str
                                choices:
                                    - enable
                                    - disable
                    classifier:
                        description:
                            - Match-conditions for the policy.
                        type: dict
                        suboptions:
                            dst_ip_prefix:
                                description:
                                    - Destination-ip address to be matched.
                                type: str
                            dst_mac:
                                description:
                                    - Destination mac address to be matched.
                                type: str
                            ether_type:
                                description:
                                    - Ether type to be matched.
                                type: int
                            service:
                                description:
                                    - Service name. Source switch.acl.service.custom.name.
                                type: str
                            src_ip_prefix:
                                description:
                                    - Source-ip address to be matched.
                                type: str
                            src_mac:
                                description:
                                    - Source mac address to be matched.
                                type: str
                            vlan_id:
                                description:
                                    - Vlan id to be matched.
                                type: int
                    description:
                        description:
                            - Description of the policy.
                        type: str
                    group:
                        description:
                            - Group ID of the policy.
                        type: int
                    id:
                        description:
                            - Ingress policy ID.
                        type: int
            description:
                description:
                    - Description of the policy.
                type: str
            filter_id:
                description:
                    - filter-id of the policy.
                type: str
            id:
                description:
                    - 802-1X Dynamic Ingress policy ID.
                required: true
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
  - name: 802-1X Radius Dynamic Ingress Policy configuration.
    fortiswitch_switch_acl_802_1x:
      state: "present"
      switch_acl_802_1x:
        access_list_entry:
         -
            action:
                count: "enable"
                drop: "enable"
            classifier:
                dst_ip_prefix: "<your_own_value>"
                dst_mac: "<your_own_value>"
                ether_type: "10"
                service: "<your_own_value> (source switch.acl.service.custom.name)"
                src_ip_prefix: "<your_own_value>"
                src_mac: "<your_own_value>"
                vlan_id: "14"
            description: "<your_own_value>"
            group: "16"
            id:  "17"
        description: "<your_own_value>"
        filter_id: "<your_own_value>"
        id:  "20"

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
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.secret_field import is_secret_field


def filter_switch_acl_802_1x_data(json):
    option_list = ['access_list_entry', 'description', 'filter_id',
                   'id']

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


def switch_acl_802_1x(data, fos):

    state = data['state']

    switch_acl_802_1x_data = data['switch_acl_802_1x']
    filtered_data = underscore_to_hyphen(filter_switch_acl_802_1x_data(switch_acl_802_1x_data))

    if state == "present" or state is True:
        return fos.set('switch.acl',
                       '802-1X',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('switch.acl',
                          '802-1X',
                          mkey=filtered_data['id'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_switch_acl(data, fos):

    fos.do_member_operation('switch.acl', '802-1X')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_acl_802_1x']:
        resp = switch_acl_802_1x(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_acl_802_1x'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "elements": "dict",
    "type": "list",
    "children": {
        "id": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True
            }
        },
        "filter_id": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True
            }
        },
        "access_list_entry": {
            "elements": "dict",
            "type": "list",
            "children": {
                "action": {
                    "type": "dict",
                    "children": {
                        "count": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.3": True,
                                        "v7.0.2": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.3": True,
                                        "v7.0.2": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True
                            }
                        },
                        "drop": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.3": True,
                                        "v7.0.2": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.3": True,
                                        "v7.0.2": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True
                    }
                },
                "group": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True
                    }
                },
                "description": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True
                    }
                },
                "classifier": {
                    "type": "dict",
                    "children": {
                        "dst_mac": {
                            "type": "string",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True
                            }
                        },
                        "ether_type": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True
                            }
                        },
                        "service": {
                            "type": "string",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True
                            }
                        },
                        "dst_ip_prefix": {
                            "type": "string",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True
                            }
                        },
                        "src_ip_prefix": {
                            "type": "string",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True
                            }
                        },
                        "src_mac": {
                            "type": "string",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True
                            }
                        },
                        "vlan_id": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True
                    }
                }
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True
            }
        },
        "description": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True
            }
        }
    },
    "revisions": {
        "v7.0.3": True,
        "v7.0.2": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'id'
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
        "switch_acl_802_1x": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_acl_802_1x"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_acl_802_1x"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_acl_802_1x")

        is_error, has_changed, result, diff = fortiswitch_switch_acl(module.params, fos)

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
