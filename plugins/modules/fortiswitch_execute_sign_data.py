#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019-2022 Fortinet, Inc.
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
module: fortiswitch_execute_sign_data
short_description: Sign data with a local certificate.
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify sign feature and data category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
version_added: 2.11
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
requirements:
    - ansible>=2.11
options:
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    execute_sign_data:
        description:
            - Sign data with a local certificate.
        default: null
        type: dict
        suboptions:
            certificate:
                description:
                    - Certificate data for the Verification.
                type: str
            signature:
                description:
                    - Signed data(Base64 Encoded) for the Verification.
                type: str
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
results:
  description: the main output of the execution
  returned: only for successful calls
  type: json
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
  - name: Sign data with a local certificate.
    execute_sign_data:
      sign_data:
        certificate: "<your_own_value>"
        signature: "<your_own_value>"
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import FortiOSHandler
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import schema_to_module_spec
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import check_schema_versioning
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG


def filter_sign_data_data(config_data):
    option_list = ['certificate','signature']
    dictionary = {}

    for attribute in option_list:
        if attribute in config_data and config_data[attribute] is not None:
            dictionary[attribute] = config_data[attribute]

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


def sign_data(data, fos):
    sign_data_data = data['execute_sign_data']
    filtered_data = underscore_to_hyphen(filter_sign_data_data(sign_data_data))
   
    return fos.call_execute_api(
        'sign',
        'data',
        data=filtered_data,
    )

def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_execute_sign_data(data, fos):
    resp = sign_data(data, fos)
    
    return not is_successful_status(resp), \
        is_successful_status(resp), \
        resp

params = {
    "type": "dict", 
    "children": {
        "certificate": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "signature": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }
    }, 
    "revisions": {
        "v7.0.3": True, 
        "v7.0.2": True, 
        "v7.0.1": True, 
        "v7.0.0": True
    }
}

def main():
    module_spec = schema_to_module_spec(params)
    fields = {
        "enable_log": {"required": False, "type": bool},
        "execute_sign_data": {
            "required": False, "type": "dict", "default": None,
            "options": { 
            }
        }
    }

    for attribute_name in module_spec['options']:
        fields["execute_sign_data"]['options'][attribute_name] = module_spec['options'][attribute_name]

    module = AnsibleModule(
        argument_spec=fields
    )

    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module)
        is_error, has_changed, result = fortiswitch_execute_sign_data(module.params, fos)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)

if __name__ == '__main__':
    main()