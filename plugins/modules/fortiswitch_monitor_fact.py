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
module: fortiswitch_monitor_fact
version_added: "1.0.0"
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
    - This module is exclusivly for FortiSwitch monitor API.
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
        elements: str
        required: false
    sorters:
        description:
            - A list of expressions to sort the returned results.
            - The items of the list are in ascending order with operator ampersand.
            - One item itself could be in decending order with a comma inside.
        type: list
        elements: str
        required: false
    formatters:
        description:
            - A list of fields to display for returned results.
        type: list
        elements: str
        required: false
    selectors:
        description:
            - A list of selectors for retrieving the fortiswitch facts.
        type: list
        elements: dict
        required: false
        suboptions:
            filters:
                description:
                    - A list of expressions to filter the returned results.
                    - The items of the list are combined as LOGICAL AND with operator ampersand.
                    - One item itself could be concatenated with a comma as LOGICAL OR.
                type: list
                elements: str
                required: false
            sorters:
                description:
                    - A list of expressions to sort the returned results.
                    - The items of the list are in ascending order with operator ampersand.
                    - One item itself could be in decending order with a comma inside.
                type: list
                elements: str
                required: false
            formatters:
                description:
                    - A list of fields to display for returned results.
                type: list
                elements: str
                required: false
            params:
                description:
                    - the parameter for each selector, see definition in above list.
                type: dict
                required: false
            selector:
                description:
                    - selector of the retrieved fortiSwitch facts
                type: str
                required: true
                choices:
                 - switch_port
                 - switch_port-speed
                 - switch_port-statistics
                 - switch_stp-state
                 - switch_trunk-state
                 - switch_loop-guard-state
                 - switch_acl-stats
                 - switch_acl-stats-ingress
                 - switch_acl-stats-egress
                 - switch_acl-stats-prelookup
                 - switch_lldp-state
                 - switch_mac-address
                 - switch_mac-address-summary
                 - system_status
                 - switch_poe-status
                 - switch_poe-summary
                 - switch_capabilities
                 - switch_dhcp-snooping-db
                 - switch_dhcp-snooping-client-db
                 - switch_dhcp-snooping-server-db
                 - switch_dhcp-snooping-client6-db
                 - switch_dhcp-snooping-server6-db
                 - switch_network-monitor-l3db
                 - switch_network-monitor-l2db
                 - switch_faceplate
                 - system_resource
                 - switch_802.1x-status
                 - system_interface-physical
                 - system_hardware-status
                 - router_routing-table
                 - switch_mclag-list
                 - switch_mclag-icl
                 - switch_flapguard-status
                 - system_fan-status
                 - system_psu-status
                 - system_flash-list
                 - hardware_cpu
                 - hardware_memory
                 - switch_qos-stats
                 - system_link-monitor-status
                 - system_ntp-status
                 - system_pcb-temp
                 - switch_modules-detail
                 - switch_modules-summary
                 - switch_modules-status
                 - switch_modules-limits
                 - switch_acl-usage
                 - switch_igmp-snooping-group
                 - system_performance-status
                 - system_upgrade-status
                 - system_flow-export-statistics
                 - system_flow-export-flows
                 - system_log
                 - system_dhcp-lease-list
                 - system_sniffer-profile-summary
                 - switch_dhcp-snooping-limit-db-details
                 - switch_cable-diag

    selector:
        description:
            - selector of the retrieved fortiSwitch facts.
        type: str
        required: false
        choices:
         - switch_port
         - switch_port-speed
         - switch_port-statistics
         - switch_stp-state
         - switch_trunk-state
         - switch_loop-guard-state
         - switch_acl-stats
         - switch_acl-stats-ingress
         - switch_acl-stats-egress
         - switch_acl-stats-prelookup
         - switch_lldp-state
         - switch_mac-address
         - switch_mac-address-summary
         - system_status
         - switch_poe-status
         - switch_poe-summary
         - switch_capabilities
         - switch_dhcp-snooping-db
         - switch_dhcp-snooping-client-db
         - switch_dhcp-snooping-server-db
         - switch_dhcp-snooping-client6-db
         - switch_dhcp-snooping-server6-db
         - switch_network-monitor-l3db
         - switch_network-monitor-l2db
         - switch_faceplate
         - system_resource
         - switch_802.1x-status
         - system_interface-physical
         - system_hardware-status
         - router_routing-table
         - switch_mclag-list
         - switch_mclag-icl
         - switch_flapguard-status
         - system_fan-status
         - system_psu-status
         - system_flash-list
         - hardware_cpu
         - hardware_memory
         - switch_qos-stats
         - system_link-monitor-status
         - system_ntp-status
         - system_pcb-temp
         - switch_modules-detail
         - switch_modules-summary
         - switch_modules-status
         - switch_modules-limits
         - switch_acl-usage
         - switch_igmp-snooping-group
         - system_performance-status
         - system_upgrade-status
         - system_flow-export-statistics
         - system_flow-export-flows
         - system_log
         - system_dhcp-lease-list
         - system_sniffer-profile-summary
         - switch_dhcp-snooping-limit-db-details
         - switch_cable-diag

    params:
        description:
            - the parameter for each selector, see definition in above list.
        type: dict
        required: false
'''

EXAMPLES = '''
- name: Get system status info
  fortinet.fortiswitch.fortiswitch_monitor_fact:
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
  description: Last method used to provision the content into FortiSwitch
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
  description: Version of the FortiSwitch
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
    "switch_port": {
        "url": "switch/port"
    },
    "switch_port-speed": {
        "url": "switch/port-speed"
    },
    "switch_port-statistics": {
        "url": "switch/port-statistics"
    },
    "switch_stp-state": {
        "url": "switch/stp-state"
    },
    "switch_trunk-state": {
        "url": "switch/trunk-state"
    },
    "switch_loop-guard-state": {
        "url": "switch/loop-guard-state"
    },
    "switch_acl-stats": {
        "url": "switch/acl-stats"
    },
    "switch_acl-stats-ingress": {
        "url": "switch/acl-stats-ingress"
    },
    "switch_acl-stats-egress": {
        "url": "switch/acl-stats-egress"
    },
    "switch_acl-stats-prelookup": {
        "url": "switch/acl-stats-prelookup"
    },
    "switch_lldp-state": {
        "url": "switch/lldp-state"
    },
    "switch_mac-address": {
        "url": "switch/mac-address"
    },
    "switch_mac-address-summary": {
        "url": "switch/mac-address-summary"
    },
    "system_status": {
        "url": "system/status"
    },
    "switch_poe-status": {
        "url": "switch/poe-status"
    },
    "switch_poe-summary": {
        "url": "switch/poe-summary"
    },
    "switch_capabilities": {
        "url": "switch/capabilities"
    },
    "switch_dhcp-snooping-db": {
        "url": "switch/dhcp-snooping-db"
    },
    "switch_dhcp-snooping-client-db": {
        "url": "switch/dhcp-snooping-client-db"
    },
    "switch_dhcp-snooping-server-db": {
        "url": "switch/dhcp-snooping-server-db"
    },
    "switch_dhcp-snooping-client6-db": {
        "url": "switch/dhcp-snooping-client6-db"
    },
    "switch_dhcp-snooping-server6-db": {
        "url": "switch/dhcp-snooping-server6-db"
    },
    "switch_network-monitor-l3db": {
        "url": "switch/network-monitor-l3db"
    },
    "switch_network-monitor-l2db": {
        "url": "switch/network-monitor-l2db"
    },
    "switch_faceplate": {
        "url": "switch/faceplate"
    },
    "system_resource": {
        "url": "system/resource"
    },
    "switch_802.1x-status": {
        "url": "switch/802.1x-status"
    },
    "system_interface-physical": {
        "url": "system/interface-physical"
    },
    "system_hardware-status": {
        "url": "system/hardware-status"
    },
    "router_routing-table": {
        "url": "router/routing-table"
    },
    "switch_mclag-list": {
        "url": "switch/mclag-list"
    },
    "switch_mclag-icl": {
        "url": "switch/mclag-icl"
    },
    "switch_flapguard-status": {
        "url": "switch/flapguard-status"
    },
    "system_fan-status": {
        "url": "system/fan-status"
    },
    "system_psu-status": {
        "url": "system/psu-status"
    },
    "system_flash-list": {
        "url": "system/flash-list"
    },
    "hardware_cpu": {
        "url": "hardware/cpu"
    },
    "hardware_memory": {
        "url": "hardware/memory"
    },
    "switch_qos-stats": {
        "url": "switch/qos-stats"
    },
    "system_link-monitor-status": {
        "url": "system/link-monitor-status"
    },
    "system_ntp-status": {
        "url": "system/ntp-status"
    },
    "system_pcb-temp": {
        "url": "system/pcb-temp"
    },
    "switch_modules-detail": {
        "url": "switch/modules-detail"
    },
    "switch_modules-summary": {
        "url": "switch/modules-summary"
    },
    "switch_modules-status": {
        "url": "switch/modules-status"
    },
    "switch_modules-limits": {
        "url": "switch/modules-limits"
    },
    "switch_acl-usage": {
        "url": "switch/acl-usage"
    },
    "switch_igmp-snooping-group": {
        "url": "switch/igmp-snooping-group"
    },
    "system_performance-status": {
        "url": "system/performance-status"
    },
    "system_upgrade-status": {
        "url": "system/upgrade-status"
    },
    "system_flow-export-statistics": {
        "url": "system/flow-export-statistics"
    },
    "system_flow-export-flows": {
        "url": "system/flow-export-flows"
    },
    "system_log": {
        "url": "system/log"
    },
    "system_dhcp-lease-list": {
        "url": "system/dhcp-lease-list"
    },
    "system_sniffer-profile-summary": {
        "url": "system/sniffer-profile-summary"
    },
    "switch_dhcp-snooping-limit-db-details": {
        "url": "switch/dhcp-snooping-limit-db-details"
    },
    "switch_cable-diag": {
        "url": "switch/cable-diag"
    }
}


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_monitor_fact(params, fos):
    selector = params['selector']
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
        "enable_log": {"required": False, "type": "bool", "default": False},
        "filters": {"required": False, "type": 'list', 'elements': 'str'},
        "sorters": {"required": False, "type": 'list', 'elements': 'str'},
        "formatters": {"required": False, "type": 'list', 'elements': 'str'},
        "params": {"required": False, "type": "dict"},
        "selector": {
            "required": False,
            "type": "str",
            "choices": [
                "switch_port",
                "switch_port-speed",
                "switch_port-statistics",
                "switch_stp-state",
                "switch_trunk-state",
                "switch_loop-guard-state",
                "switch_acl-stats",
                "switch_acl-stats-ingress",
                "switch_acl-stats-egress",
                "switch_acl-stats-prelookup",
                "switch_lldp-state",
                "switch_mac-address",
                "switch_mac-address-summary",
                "system_status",
                "switch_poe-status",
                "switch_poe-summary",
                "switch_capabilities",
                "switch_dhcp-snooping-db",
                "switch_dhcp-snooping-client-db",
                "switch_dhcp-snooping-server-db",
                "switch_dhcp-snooping-client6-db",
                "switch_dhcp-snooping-server6-db",
                "switch_network-monitor-l3db",
                "switch_network-monitor-l2db",
                "switch_faceplate",
                "system_resource",
                "switch_802.1x-status",
                "system_interface-physical",
                "system_hardware-status",
                "router_routing-table",
                "switch_mclag-list",
                "switch_mclag-icl",
                "switch_flapguard-status",
                "system_fan-status",
                "system_psu-status",
                "system_flash-list",
                "hardware_cpu",
                "hardware_memory",
                "switch_qos-stats",
                "system_link-monitor-status",
                "system_ntp-status",
                "system_pcb-temp",
                "switch_modules-detail",
                "switch_modules-summary",
                "switch_modules-status",
                "switch_modules-limits",
                "switch_acl-usage",
                "switch_igmp-snooping-group",
                "system_performance-status",
                "system_upgrade-status",
                "system_flow-export-statistics",
                "system_flow-export-flows",
                "system_log",
                "system_dhcp-lease-list",
                "system_sniffer-profile-summary",
                "switch_dhcp-snooping-limit-db-details",
                "switch_cable-diag",
            ],
        },
        "selectors": {
            "required": False,
            "type": "list",
            "elements": "dict",
            "options": {
                "filters": {"required": False, "type": 'list', 'elements': 'str'},
                "sorters": {"required": False, "type": 'list', 'elements': 'str'},
                "formatters": {"required": False, "type": 'list', 'elements': 'str'},
                "params": {"required": False, "type": "dict"},
                "selector": {
                    "required": True,
                    "type": "str",
                    "choices": [
                        "switch_port",
                        "switch_port-speed",
                        "switch_port-statistics",
                        "switch_stp-state",
                        "switch_trunk-state",
                        "switch_loop-guard-state",
                        "switch_acl-stats",
                        "switch_acl-stats-ingress",
                        "switch_acl-stats-egress",
                        "switch_acl-stats-prelookup",
                        "switch_lldp-state",
                        "switch_mac-address",
                        "switch_mac-address-summary",
                        "system_status",
                        "switch_poe-status",
                        "switch_poe-summary",
                        "switch_capabilities",
                        "switch_dhcp-snooping-db",
                        "switch_dhcp-snooping-client-db",
                        "switch_dhcp-snooping-server-db",
                        "switch_dhcp-snooping-client6-db",
                        "switch_dhcp-snooping-server6-db",
                        "switch_network-monitor-l3db",
                        "switch_network-monitor-l2db",
                        "switch_faceplate",
                        "system_resource",
                        "switch_802.1x-status",
                        "system_interface-physical",
                        "system_hardware-status",
                        "router_routing-table",
                        "switch_mclag-list",
                        "switch_mclag-icl",
                        "switch_flapguard-status",
                        "system_fan-status",
                        "system_psu-status",
                        "system_flash-list",
                        "hardware_cpu",
                        "hardware_memory",
                        "switch_qos-stats",
                        "system_link-monitor-status",
                        "system_ntp-status",
                        "system_pcb-temp",
                        "switch_modules-detail",
                        "switch_modules-summary",
                        "switch_modules-status",
                        "switch_modules-limits",
                        "switch_acl-usage",
                        "switch_igmp-snooping-group",
                        "system_performance-status",
                        "system_upgrade-status",
                        "system_flow-export-statistics",
                        "system_flow-export-flows",
                        "system_log",
                        "system_dhcp-lease-list",
                        "system_sniffer-profile-summary",
                        "switch_dhcp-snooping-limit-db-details",
                        "switch_cable-diag",
                    ],
                },
            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    if module.params['selector'] and module.params['selectors'] or \
            not module.params['selector'] and not module.params['selectors']:
        module.fail_json(msg='please use selector or selectors in a task.')

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        # Logging for fact module could be disabled/enabled.
        if 'enable_log' in module.params:
            connection.set_custom_option('enable_log', module.params['enable_log'])
        else:
            connection.set_custom_option('enable_log', False)

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
                is_error_local, has_changed_local, result_local = fortiswitch_monitor_fact(selector_obj, fos)

                is_error = is_error or is_error_local
                has_changed = has_changed or has_changed_local
                result.append(result_local)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortiSwitch system and galaxy, see more details by specifying option -vvv")

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
