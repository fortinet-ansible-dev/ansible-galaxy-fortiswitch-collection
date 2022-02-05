#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2020-2021 Fortinet, Inc.
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
module: fortiswitch_monitor_fact
version_added: "2.11"
short_description: Retrieve Facts of FortiSwitch Monitor Objects.
description:
    - Collects monitor facts from network devices running the fortiswitch operating system.
      This facts module will only collect those facts which user specified in playbook.
author:
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@fshen01)
notes:
    - Different selector may have different parameters, users are expected to look up them for a specific selector.
    - For some selectors, the objects are global, no params are allowed to appear.
    - Not all parameters are required for a slector.
    - This module is exclusivly for FortiOS monitor API.
    - The result of API request is stored in results.
requirements:
    - install galaxy collection fortinet.fortiswitch >= 1.0.0.
options:
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    filters:
        description:
            - A list of expressions to filter the returned results.
            - The items of the list are combined as LOGICAL AND with operator ampersand.
            - One item itself could be concatenated with a comma as LOGICAL OR.
        type: list
        required: false
    sorters:
        description:
            - A list of expressions to sort the returned results.
            - The items of the list are in ascending order with operator ampersand.
            - One item itself could be in decending order with a comma inside.
        type: list
        required: false
    formatters:
        description:
            - A list of fields to display for returned results.
        type: list
        required: false
    selector:
        description:
            - selector of the retrieved fortimanager facts
        type: str
        required: true
        choices:
         - system_dhcp-lease-list
         - switch_port
         - switch_dhcp-snooping-client-db
         - switch_poe-summary
         - switch_acl-stats-egress
         - system_performance-status
         - system_status
         - switch_acl-usage
         - switch_modules-detail
         - switch_port-statistics
         - switch_acl-stats-ingress
         - system_sniffer-profile-summary
         - switch_modules-summary
         - switch_poe-status
         - switch_acl-stats-prelookup
         - switch_mac-address
         - switch_mac-address-summary
         - system_hardware-status
         - switch_trunk-state
         - system_interface-physical
         - system_flash-list
         - switch_loop-guard-state
         - switch_network-monitor-l2db
         - hardware_cpu
         - switch_mclag-list
         - switch_network-monitor-l3db
         - switch_acl-stats
         - system_log
         - switch_dhcp-snooping-limit-db-details
         - switch_qos-stats
         - switch_dhcp-snooping-db
         - system_flow-export-statistics
         - router_routing-table
         - system_psu-status
         - switch_port-speed
         - system_pcb-temp
         - switch_modules-status
         - switch_modules-limits
         - system_ntp-status
         - switch_dhcp-snooping-client6-db
         - switch_igmp-snooping-group
         - switch_capabilities
         - switch_802.1x-status
         - switch_dhcp-snooping-server6-db
         - switch_lldp-state
         - system_link-monitor-status
         - switch_stp-state
         - switch_faceplate
         - hardware_memory
         - system_fan-status
         - system_flow-export-flows
         - switch_cable-diag
         - system_upgrade-status
         - system_resource
         - switch_flapguard-status
         - switch_dhcp-snooping-server-db
         - switch_mclag-icl
         
    params:
        description:
            - the parameter for each selector, see definition in above list.
        type: dict
        required: false
'''

EXAMPLES = '''
- hosts: fortiswitch01
  connection: httpapi
  collections:
  - fortinet.fortiswitch
  vars:
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: no
   ansible_httpapi_port: 443
  tasks:
  - fortiswitch_monitor_fact:
       formatters:
            - model_name
       filters:
            - model_name==FortiSwitch
       selectors: 
          - system_status

'''

RETURN = '''
build:
  description: Build number of the fortiswitch image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'GET'
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "firmware"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "system"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
ansible_facts:
  description: The list of fact subsets collected from the device
  returned: always
  type: dict

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import FortiOSHandler
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG

module_selectors_defs = {
    "system_dhcp-lease-list": {
        "url": "system/dhcp-lease-list"
    },
    "switch_port": {
        "url": "switch/port"
    },
    "switch_dhcp-snooping-client-db": {
        "url": "switch/dhcp-snooping-client-db"
    },
    "switch_poe-summary": {
        "url": "switch/poe-summary"
    },
    "switch_acl-stats-egress": {
        "url": "switch/acl-stats-egress"
    },
    "system_performance-status": {
        "url": "system/performance-status"
    },
    "system_status": {
        "url": "system/status"
    },
    "switch_acl-usage": {
        "url": "switch/acl-usage"
    },
    "switch_modules-detail": {
        "url": "switch/modules-detail"
    },
    "switch_port-statistics": {
        "url": "switch/port-statistics"
    },
    "switch_acl-stats-ingress": {
        "url": "switch/acl-stats-ingress"
    },
    "system_sniffer-profile-summary": {
        "url": "system/sniffer-profile-summary"
    },
    "switch_modules-summary": {
        "url": "switch/modules-summary"
    },
    "switch_poe-status": {
        "url": "switch/poe-status"
    },
    "switch_acl-stats-prelookup": {
        "url": "switch/acl-stats-prelookup"
    },
    "switch_mac-address": {
        "url": "switch/mac-address"
    },
    "switch_mac-address-summary": {
        "url": "switch/mac-address-summary"
    },
    "system_hardware-status": {
        "url": "system/hardware-status"
    },
    "switch_trunk-state": {
        "url": "switch/trunk-state"
    },
    "system_interface-physical": {
        "url": "system/interface-physical"
    },
    "system_flash-list": {
        "url": "system/flash-list"
    },
    "switch_loop-guard-state": {
        "url": "switch/loop-guard-state"
    },
    "switch_network-monitor-l2db": {
        "url": "switch/network-monitor-l2db"
    },
    "hardware_cpu": {
        "url": "hardware/cpu"
    },
    "switch_mclag-list": {
        "url": "switch/mclag-list"
    },
    "switch_network-monitor-l3db": {
        "url": "switch/network-monitor-l3db"
    },
    "switch_acl-stats": {
        "url": "switch/acl-stats"
    },
    "system_log": {
        "url": "system/log"
    },
    "switch_dhcp-snooping-limit-db-details": {
        "url": "switch/dhcp-snooping-limit-db-details"
    },
    "switch_qos-stats": {
        "url": "switch/qos-stats"
    },
    "switch_dhcp-snooping-db": {
        "url": "switch/dhcp-snooping-db"
    },
    "system_flow-export-statistics": {
        "url": "system/flow-export-statistics"
    },
    "router_routing-table": {
        "url": "router/routing-table"
    },
    "system_psu-status": {
        "url": "system/psu-status"
    },
    "switch_port-speed": {
        "url": "switch/port-speed"
    },
    "system_pcb-temp": {
        "url": "system/pcb-temp"
    },
    "switch_modules-status": {
        "url": "switch/modules-status"
    },
    "switch_modules-limits": {
        "url": "switch/modules-limits"
    },
    "system_ntp-status": {
        "url": "system/ntp-status"
    },
    "switch_dhcp-snooping-client6-db": {
        "url": "switch/dhcp-snooping-client6-db"
    },
    "switch_igmp-snooping-group": {
        "url": "switch/igmp-snooping-group"
    },
    "switch_capabilities": {
        "url": "switch/capabilities"
    },
    "switch_802.1x-status": {
        "url": "switch/802.1x-status"
    },
    "switch_dhcp-snooping-server6-db": {
        "url": "switch/dhcp-snooping-server6-db"
    },
    "switch_lldp-state": {
        "url": "switch/lldp-state"
    },
    "system_link-monitor-status": {
        "url": "system/link-monitor-status"
    },
    "switch_stp-state": {
        "url": "switch/stp-state"
    },
    "switch_faceplate": {
        "url": "switch/faceplate"
    },
    "hardware_memory": {
        "url": "hardware/memory"
    },
    "system_fan-status": {
        "url": "system/fan-status"
    },
    "system_flow-export-flows": {
        "url": "system/flow-export-flows"
    },
    "switch_cable-diag": {
        "url": "switch/cable-diag"
    },
    "system_upgrade-status": {
        "url": "system/upgrade-status"
    },
    "system_resource": {
        "url": "system/resource"
    },
    "switch_flapguard-status": {
        "url": "switch/flapguard-status"
    },
    "switch_dhcp-snooping-server-db": {
        "url": "switch/dhcp-snooping-server-db"
    },
    "switch_mclag-icl": {
        "url": "switch/mclag-icl"
    }
}


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


# def validate_parameters(params, fos):
#     #parameter validation will not block task, warning will be provided in case of parameters validation.
#     selector = params['selector']
#     selector_params = params.get('params', {})

#     if selector not in module_selectors_defs:
#       return False, { "message": "unknown selector: " + selector }

#     if selector_params:
#         for param_key, param_value in selector_params.items():
#             if type(param_value) not in [bool, int, str]:
#                 return False, {'message': 'value of param:%s must be atomic' % (param_key)}

#     definition = module_selectors_defs.get(selector, {})

#     if not params or len(params) == 0 or len(definition) == 0:
#         return True, {}

#     acceptable_param_names = list(definition.get('params').keys())
#     provided_param_names = list(params.keys() if params else [])

#     params_valid = True
#     for param_name in acceptable_param_names:
#         if param_name not in provided_param_names and eval(module_selectors_defs[selector]['params'][param_name]['required']):
#             params_valid = False
#             break
#     if params_valid:
#         for param_name in provided_param_names:
#             if param_name not in acceptable_param_names:
#                 params_valid = False
#                 break
#     if not params_valid:
#         param_summary = ['%s(%s, %s)' % (param_name, param['type'], 'required' if eval(param['required']) else 'optional') for param_name, param in module_selectors_defs[selector]['params'].items()]
#         fos._module.warn("selector:%s expects params:%s" % (selector, str(param_summary)))
#     return True, {}

def fortiswitch_monitor_fact(params, fos):
    # valid, result = validate_parameters(params, fos)
    # if not valid:
    #     return True, False, result

    selector = params['selector']
    selector_params = params['params']

    url_params = dict()
    if params['filters'] and len(params['filters']):
        filter_body = params['filters'][0]
        for filter_item in params['filters'][1:]:
            filter_body = "%s&filter=%s" % (filter_body, filter_item)
        url_params['filter'] = filter_body
    if params['sorters'] and len(params['sorters']):
        sorter_body = params['sorters'][0]
        for sorter_item in params['sorters'][1:]:
            sorter_body = "%s&sort=%s" % (sorter_body, sorter_item)
        url_params['sort'] = sorter_body
    if params['formatters'] and len(params['formatters']):
        formatter_body = params['formatters'][0]
        for formatter_item in params['formatters'][1:]:
            formatter_body = '%s|%s' % (formatter_body, formatter_item)
        url_params['format'] = formatter_body
    if params['params']:
        for selector_param_key, selector_param in params['params'].items():
            url_params[selector_param_key] = selector_param

    fact = fos.monitor_get(module_selectors_defs[selector]['url'], url_params)

    return not is_successful_status(fact), False, fact

def main():
    fields = {
        "enable_log": {"required": False, "type": bool},
        "filters": {"required": False, "type": 'list'},
        "sorters": {"required": False, "type": 'list'},
        "formatters": {"required": False, "type": 'list'},
        "params": {"required": False, "type": "dict" },
        "selector": {
            "required": False,
            "type": "str",
            "options": [
                "system_dhcp-lease-list",
                "switch_port",
                "switch_dhcp-snooping-client-db",
                "switch_poe-summary",
                "switch_acl-stats-egress",
                "system_performance-status",
                "system_status",
                "switch_acl-usage",
                "switch_modules-detail",
                "switch_port-statistics",
                "switch_acl-stats-ingress",
                "system_sniffer-profile-summary",
                "switch_modules-summary",
                "switch_poe-status",
                "switch_acl-stats-prelookup",
                "switch_mac-address",
                "switch_mac-address-summary",
                "system_hardware-status",
                "switch_trunk-state",
                "system_interface-physical",
                "system_flash-list",
                "switch_loop-guard-state",
                "switch_network-monitor-l2db",
                "hardware_cpu",
                "switch_mclag-list",
                "switch_network-monitor-l3db",
                "switch_acl-stats",
                "system_log",
                "switch_dhcp-snooping-limit-db-details",
                "switch_qos-stats",
                "switch_dhcp-snooping-db",
                "system_flow-export-statistics",
                "router_routing-table",
                "system_psu-status",
                "switch_port-speed",
                "system_pcb-temp",
                "switch_modules-status",
                "switch_modules-limits",
                "system_ntp-status",
                "switch_dhcp-snooping-client6-db",
                "switch_igmp-snooping-group",
                "switch_capabilities",
                "switch_802.1x-status",
                "switch_dhcp-snooping-server6-db",
                "switch_lldp-state",
                "system_link-monitor-status",
                "switch_stp-state",
                "switch_faceplate",
                "hardware_memory",
                "system_fan-status",
                "system_flow-export-flows",
                "switch_cable-diag",
                "system_upgrade-status",
                "system_resource",
                "switch_flapguard-status",
                "switch_dhcp-snooping-server-db",
                "switch_mclag-icl",
                ],
        },
        "selectors": {
            "required": False,
            "type": "list",
            "elements": "dict",
            "options": {
                "filters": {"required": False, "type": 'list'},
                "sorters": {"required": False, "type": 'list'},
                "formatters": {"required": False, "type": 'list'},
                "params": {"required": False, "type": "dict" },
                "selector": {
                    "required": False,
                    "type": "str",
                    "options": [
                        "system_dhcp-lease-list",
                        "switch_port",
                        "switch_dhcp-snooping-client-db",
                        "switch_poe-summary",
                        "switch_acl-stats-egress",
                        "system_performance-status",
                        "system_status",
                        "switch_acl-usage",
                        "switch_modules-detail",
                        "switch_port-statistics",
                        "switch_acl-stats-ingress",
                        "system_sniffer-profile-summary",
                        "switch_modules-summary",
                        "switch_poe-status",
                        "switch_acl-stats-prelookup",
                        "switch_mac-address",
                        "switch_mac-address-summary",
                        "system_hardware-status",
                        "switch_trunk-state",
                        "system_interface-physical",
                        "system_flash-list",
                        "switch_loop-guard-state",
                        "switch_network-monitor-l2db",
                        "hardware_cpu",
                        "switch_mclag-list",
                        "switch_network-monitor-l3db",
                        "switch_acl-stats",
                        "system_log",
                        "switch_dhcp-snooping-limit-db-details",
                        "switch_qos-stats",
                        "switch_dhcp-snooping-db",
                        "system_flow-export-statistics",
                        "router_routing-table",
                        "system_psu-status",
                        "switch_port-speed",
                        "system_pcb-temp",
                        "switch_modules-status",
                        "switch_modules-limits",
                        "system_ntp-status",
                        "switch_dhcp-snooping-client6-db",
                        "switch_igmp-snooping-group",
                        "switch_capabilities",
                        "switch_802.1x-status",
                        "switch_dhcp-snooping-server6-db",
                        "switch_lldp-state",
                        "system_link-monitor-status",
                        "switch_stp-state",
                        "switch_faceplate",
                        "hardware_memory",
                        "system_fan-status",
                        "system_flow-export-flows",
                        "switch_cable-diag",
                        "system_upgrade-status",
                        "system_resource",
                        "switch_flapguard-status",
                        "switch_dhcp-snooping-server-db",
                        "switch_mclag-icl",
                        ],
                },
            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        # Logging for fact module could be disabled/enabled.
        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)

        fos = FortiOSHandler(connection, module)

        if module.params['selector']:
            is_error, has_changed, result = fortiswitch_monitor_fact(module.params, fos)
        else:
            params = module.params
            selectors = params['selectors']
            is_error = False
            has_changed = False
            result = []
            for selector_obj in selectors:
                per_selector = {
                    **selector_obj,
                }
                is_error_local, has_changed_local, result_local = fortiswitch_monitor_fact(per_selector, fos)

                is_error = is_error or is_error_local
                has_changed = has_changed or has_changed_local
                result.append(result_local)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortOS system and galaxy, see more details by specifying option -vvv")

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