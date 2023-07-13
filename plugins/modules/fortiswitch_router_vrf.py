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
module: fortiswitch_router_vrf
short_description: VRF configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and vrf category.
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
    router_vrf:
        description:
            - VRF configuration.
        default: null
        type: dict
        suboptions:
            name:
                description:
                    - Name.
                required: true
                type: str
            vrfid:
                description:
                    - VRF ID.
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
  - name: VRF configuration.
    fortiswitch_router_vrf:
      state: "present"
      router_vrf:
        name: "default_name_3"
        vrfid: "4"

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


def filter_router_vrf_data(json):
    option_list = ['name', 'vrfid']

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


def router_vrf(data, fos, check_mode=False):
    state = data['state']
    router_vrf_data = data['router_vrf']
    filtered_data = underscore_to_hyphen(filter_router_vrf_data(router_vrf_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('router', 'vrf', filtered_data)
        current_data = fos.get('router', 'vrf', mkey=mkey)
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
        return fos.set('router',
                       'vrf',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('router',
                          'vrf',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_router(data, fos, check_mode):
    fos.do_member_operation('router', 'vrf')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['router_vrf']:
        resp = router_vrf(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('router_vrf'))
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
        "vrfid": {
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
            "name": "vrfid",
            "help": "VRF ID.",
            "category": "unitary"
        },
        "name": {
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
            "name": "name",
            "help": "Name.",
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
    "name": "vrf",
    "help": "VRF configuration.",
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
        "router_vrf": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["router_vrf"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["router_vrf"]['options'][attribute_name]['required'] = True

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=True)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "router_vrf")
        is_error, has_changed, result, diff = fortiswitch_router(module.params, fos, module.check_mode)
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
