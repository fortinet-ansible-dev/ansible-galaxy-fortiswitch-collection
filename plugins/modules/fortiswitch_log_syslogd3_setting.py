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
module: fortiswitch_log_syslogd3_setting
short_description: Settings for remote syslog server in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify log_syslogd3 feature and setting category.
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
    
    log_syslogd3_setting:
        description:
            - Settings for remote syslog server.
        default: null
        type: dict
        suboptions:
            certificate:
                description:
                    - Certificate used to communicate with Syslog server. Source system.certificate.local.name.
                type: str
            csv:
                description:
                    - Whether to enable CSV.
                type: str
                choices:
                    - enable
                    - disable
            enc_algorithm:
                description:
                    - Enable/disable reliable syslogging with TLS encryption.
                type: str
                choices:
                    - high-medium
                    - high
                    - low
                    - disable
            facility:
                description:
                    - Which facility for remote syslog.
                type: str
                choices:
                    - kernel
                    - user
                    - mail
                    - daemon
                    - auth
                    - syslog
                    - lpr
                    - news
                    - uucp
                    - cron
                    - authpriv
                    - ftp
                    - ntp
                    - audit
                    - alert
                    - clock
                    - local0
                    - local1
                    - local2
                    - local3
                    - local4
                    - local5
                    - local6
                    - local7
            mode:
                description:
                    - Remote syslog logging over UDP/Reliable TCP.
                type: str
                choices:
                    - udp
                    - legacy-reliable
                    - reliable
            override:
                description:
                    - Override syslog settings or use the global settings.
                type: str
            port:
                description:
                    - Port that the server listens at.
                type: int
            server:
                description:
                    - Address of the remote syslog server.
                type: str
            source_ip:
                description:
                    - Source IP address of the syslog.
                type: str
            status:
                description:
                    - Whether to enable remote syslog log.
                type: str
                choices:
                    - enable
                    - disable
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
  - name: Settings for remote syslog server.
    fortiswitch_log_syslogd3_setting:
      state: "present"
      log_syslogd3_setting:
        certificate: "<your_own_value> (source system.certificate.local.name)"
        csv: "enable"
        enc_algorithm: "high-medium"
        facility: "kernel"
        mode: "udp"
        override: "<your_own_value>"
        port: "9"
        server: "192.168.100.40"
        source_ip: "84.230.14.43"
        status: "enable"

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
def filter_log_syslogd3_setting_data(json):
    option_list = ['certificate', 'csv', 'enc_algorithm',
                   'facility', 'mode', 'override',
                   'port', 'server', 'source_ip',
                   'status' ]
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

def log_syslogd3_setting(data, fos):
    log_syslogd3_setting_data = data['log_syslogd3_setting']
    filtered_data = underscore_to_hyphen(filter_log_syslogd3_setting_data(log_syslogd3_setting_data))

    
    return fos.set('log.syslogd3',
                    'setting',
                    data=filtered_data,
                    )
    

def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404




def fortiswitch_log_syslogd3(data, fos):

    fos.do_member_operation('log_syslogd3_setting')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['log_syslogd3_setting']:
        resp = log_syslogd3_setting(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('log_syslogd3_setting'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp



versioned_schema = {
    "type": "dict", 
    "children": {
        "status": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }
            ], 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "csv": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }
            ], 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "certificate": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "facility": {
            "type": "string", 
            "options": [
                {
                    "value": "kernel", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "user", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "mail", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "daemon", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "auth", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "syslog", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "lpr", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "news", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "uucp", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "cron", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "authpriv", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "ftp", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "ntp", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "audit", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "alert", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "clock", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "local0", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "local1", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "local2", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "local3", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "local4", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "local5", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "local6", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "local7", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }
            ], 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "source_ip": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "server": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "mode": {
            "type": "string", 
            "options": [
                {
                    "value": "udp", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "legacy-reliable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "reliable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }
            ], 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "override": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "enc_algorithm": {
            "type": "string", 
            "options": [
                {
                    "value": "high-medium", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "high", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "low", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }
            ], 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "port": {
            "type": "integer", 
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
        "log_syslogd3_setting": {
            "required": False, "type": "dict", "default": None,
            "options": { 
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["log_syslogd3_setting"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["log_syslogd3_setting"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "log_syslogd3_setting")
        
        is_error, has_changed, result = fortiswitch_log_syslogd3(module.params, fos)
        
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