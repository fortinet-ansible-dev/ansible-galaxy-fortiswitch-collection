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
module: fortiswitch_router_isis
short_description: ISIS configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and isis category.
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

    router_isis:
        description:
            - ISIS configuration.
        default: null
        type: dict
        suboptions:
            auth_keychain_area:
                description:
                    - IS-IS area authentication key-chain. Applicable when area"s auth mode is md5.
                type: str
            auth_keychain_domain:
                description:
                    - IS-IS domain authentication key-chain. Applicable when domain"s auth mode is md5.
                type: str
            auth_mode_area:
                description:
                    - IS-IS area(level-1) authentication mode.
                type: str
                choices:
                    - 'password'
                    - 'md5'
            auth_mode_domain:
                description:
                    - ISIS domain(level-2) authentication mode.
                type: str
                choices:
                    - 'password'
                    - 'md5'
            auth_password_area:
                description:
                    - IS-IS area(level-1) authentication password. Applicable when area"s auth mode is password.
                type: str
            auth_password_domain:
                description:
                    - IS-IS domain(level-2) authentication password. Applicable when domain"s auth mode is password.
                type: str
            auth_sendonly_area:
                description:
                    - Enable authentication send-only for level 1 SNP PDUs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_sendonly_domain:
                description:
                    - Enable authentication send-only for level 2 SNP PDUs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_information_level:
                description:
                    - Distribute default route into level"s LSP.
                type: str
                choices:
                    - 'level_1_2'
                    - 'level_1'
                    - 'level_2'
            default_information_level6:
                description:
                    - Distribute ipv6 default route into level"s LSP.
                type: str
                choices:
                    - 'level_1_2'
                    - 'level_1'
                    - 'level_2'
            default_information_metric:
                description:
                    - Default information metric.
                type: int
            default_information_metric6:
                description:
                    - Default ipv6 route metric.
                type: int
            default_information_originate:
                description:
                    - Enable/disable generation of default route.
                type: str
                choices:
                    - 'enable'
                    - 'always'
                    - 'disable'
            default_information_originate6:
                description:
                    - Enable/disable generation of default ipv6 route.
                type: str
                choices:
                    - 'enable'
                    - 'always'
                    - 'disable'
            ignore_attached_bit:
                description:
                    - Ignore Attached bit on incoming L1 LSP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            interface:
                description:
                    - IS-IS interface configuration.
                type: list
                elements: dict
                suboptions:
                    auth_keychain_hello:
                        description:
                            - Hello PDU authentication key-chain. Applicable when hello"s auth mode is md5.
                        type: str
                    auth_mode_hello:
                        description:
                            - Hello PDU authentication mode.
                        type: str
                        choices:
                            - 'md5'
                            - 'password'
                    auth_password_hello:
                        description:
                            - Hello PDU authentication password. Applicable when hello"s auth mode is password.
                        type: str
                    bfd:
                        description:
                            - Bidirectional Forwarding Detection (BFD).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bfd6:
                        description:
                            - Ipv6 Bidirectional Forwarding Detection (BFD).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    circuit_type:
                        description:
                            - IS-IS interface"s circuit type.
                        type: str
                        choices:
                            - 'level_1_2'
                            - 'level_1'
                            - 'level_2'
                    csnp_interval_l1:
                        description:
                            - Level 1 CSNP interval.
                        type: int
                    csnp_interval_l2:
                        description:
                            - Level 2 CSNP interval.
                        type: int
                    hello_interval_l1:
                        description:
                            - Level 1 hello interval.
                        type: int
                    hello_interval_l2:
                        description:
                            - Level 2 hello interval.
                        type: int
                    hello_multiplier_l1:
                        description:
                            - Level 1 multiplier for Hello holding time.
                        type: int
                    hello_multiplier_l2:
                        description:
                            - Level 2 multiplier for Hello holding time.
                        type: int
                    hello_padding:
                        description:
                            - Enable padding to IS-IS hello packets.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    metric_l1:
                        description:
                            - Level 1 metric for interface.
                        type: int
                    metric_l2:
                        description:
                            - Level 2 metric for interface.
                        type: int
                    name:
                        description:
                            - IS-IS interface name
                        type: str
                    passive:
                        description:
                            - Set this interface as passive.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    priority_l1:
                        description:
                            - Level 1 priority.
                        type: int
                    priority_l2:
                        description:
                            - Level 2 priority.
                        type: int
                    status:
                        description:
                            - Enable the interface for IS-IS.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status6:
                        description:
                            - Enable/disable interface for ipv6 IS-IS.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    wide_metric_l1:
                        description:
                            - Level 1 wide metric for interface.
                        type: int
                    wide_metric_l2:
                        description:
                            - Level 2 wide metric for interface.
                        type: int
            is_type:
                description:
                    - IS-type.
                type: str
                choices:
                    - 'level_1_2'
                    - 'level_1'
                    - 'level_2_only'
            log_neighbour_changes:
                description:
                    - Enable logging of ISIS neighbour"s changes
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            lsp_gen_interval_l1:
                description:
                    - Minimum interval for level 1 LSP regenerating.
                type: int
            lsp_gen_interval_l2:
                description:
                    - Minimum interval for level 2 LSP regenerating.
                type: int
            lsp_refresh_interval:
                description:
                    - LSP refresh time in seconds.
                type: int
            max_lsp_lifetime:
                description:
                    - Maximum LSP lifetime in seconds.
                type: int
            metric_style:
                description:
                    - Use old-style (ISO 10589) or new-style packet formats.
                type: str
                choices:
                    - 'narrow'
                    - 'wide'
                    - 'transition'
            net:
                description:
                    - IS-IS net configuration.
                type: list
                elements: dict
                suboptions:
                    net:
                        description:
                            - isis net xx.xxxx. ... .xxxx.xx
                        type: str
            overload_bit:
                description:
                    - Signal other routers not to use us in SPF.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redistribute:
                description:
                    - IS-IS redistribute protocols.
                type: list
                elements: dict
                suboptions:
                    level:
                        description:
                            - level.
                        type: str
                        choices:
                            - 'level_1_2'
                            - 'level_1'
                            - 'level_2'
                    metric:
                        description:
                            - metric.
                        type: int
                    metric_type:
                        description:
                            - metric type.
                        type: str
                        choices:
                            - 'external'
                            - 'internal'
                    protocol:
                        description:
                            - protocol name.
                        type: str
                    routemap:
                        description:
                            - routemap name.
                        type: str
                    status:
                        description:
                            - status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            redistribute6:
                description:
                    - IS-IS redistribute v6 protocols.
                type: list
                elements: dict
                suboptions:
                    level:
                        description:
                            - level.
                        type: str
                        choices:
                            - 'level_1_2'
                            - 'level_1'
                            - 'level_2'
                    metric:
                        description:
                            - metric.
                        type: int
                    protocol:
                        description:
                            - protocol name.
                        type: str
                    routemap:
                        description:
                            - routemap name.
                        type: str
                    status:
                        description:
                            - status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            redistribute6_l1:
                description:
                    - Redistribute level 1 v6 routes into level 2.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redistribute6_l1_list:
                description:
                    - Access-list for redistribute v6 routes from l1 to l2.
                type: str
            redistribute_l1:
                description:
                    - Redistribute level 1 routes into level 2.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redistribute_l1_list:
                description:
                    - Access-list for redistribute l1 to l2.
                type: str
            router_id:
                description:
                    - Router ID.
                type: str
            spf_interval_exp_l1:
                description:
                    - Level 1 SPF minimum calculation delay in secs.
                type: int
            spf_interval_exp_l2:
                description:
                    - Level 2 SPF minimum calculation delay in secs.
                type: int
            summary_address:
                description:
                    - IS-IS summary addresses.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Summary address entry id.
                        type: int
                    level:
                        description:
                            - Level.
                        type: str
                        choices:
                            - 'level_1_2'
                            - 'level_1'
                            - 'level_2'
                    prefix:
                        description:
                            - prefix.
                        type: str
            summary_address6:
                description:
                    - IS-IS summary ipv6 addresses.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Summary address entry id.
                        type: int
                    level:
                        description:
                            - Level.
                        type: str
                        choices:
                            - 'level_1_2'
                            - 'level_1'
                            - 'level_2'
                    prefix6:
                        description:
                            - IPv6 prefix
                        type: str
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
  - name: ISIS configuration.
    fortiswitch_router_isis:
      router_isis:
        auth_keychain_area: "<your_own_value> (source router.key_chain.name)"
        auth_keychain_domain: "<your_own_value> (source router.key_chain.name)"
        auth_mode_area: "password"
        auth_mode_domain: "password"
        auth_password_area: "<your_own_value>"
        auth_password_domain: "<your_own_value>"
        auth_sendonly_area: "enable"
        auth_sendonly_domain: "enable"
        default_information_level: "level-1-2"
        default_information_level6: "level-1-2"
        default_information_metric: "13"
        default_information_metric6: "14"
        default_information_originate: "enable"
        default_information_originate6: "enable"
        ignore_attached_bit: "enable"
        interface:
         -
            auth_keychain_hello: "<your_own_value> (source router.key_chain.name)"
            auth_mode_hello: "md5"
            auth_password_hello: "<your_own_value>"
            bfd: "enable"
            bfd6: "enable"
            circuit_type: "level-1-2"
            csnp_interval_l1: "25"
            csnp_interval_l2: "26"
            hello_interval_l1: "27"
            hello_interval_l2: "28"
            hello_multiplier_l1: "29"
            hello_multiplier_l2: "30"
            hello_padding: "enable"
            metric_l1: "32"
            metric_l2: "33"
            name: "default_name_34 (source system.interface.name)"
            passive: "enable"
            priority_l1: "36"
            priority_l2: "37"
            status: "enable"
            status6: "enable"
            wide_metric_l1: "40"
            wide_metric_l2: "41"
        is_type: "level-1-2"
        log_neighbour_changes: "enable"
        lsp_gen_interval_l1: "44"
        lsp_gen_interval_l2: "45"
        lsp_refresh_interval: "46"
        max_lsp_lifetime: "47"
        metric_style: "narrow"
        net:
         -
            net: "<your_own_value>"
        overload_bit: "enable"
        redistribute:
         -
            level: "level-1-2"
            metric: "54"
            metric_type: "external"
            protocol: "<your_own_value>"
            routemap: "<your_own_value> (source router.route_map.name)"
            status: "enable"
        redistribute_l1: "enable"
        redistribute_l1_list: "<your_own_value> (source router.access_list.name)"
        redistribute6:
         -
            level: "level-1-2"
            metric: "63"
            protocol: "<your_own_value>"
            routemap: "<your_own_value> (source router.route_map.name)"
            status: "enable"
        redistribute6_l1: "enable"
        redistribute6_l1_list: "<your_own_value> (source router.access_list6.name)"
        router_id: "<your_own_value>"
        spf_interval_exp_l1: "70"
        spf_interval_exp_l2: "71"
        summary_address:
         -
            id:  "73"
            level: "level-1-2"
            prefix: "<your_own_value>"
        summary_address6:
         -
            id:  "77"
            level: "level-1-2"
            prefix6: "<your_own_value>"

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


def filter_router_isis_data(json):
    option_list = ['auth_keychain_area', 'auth_keychain_domain', 'auth_mode_area',
                   'auth_mode_domain', 'auth_password_area', 'auth_password_domain',
                   'auth_sendonly_area', 'auth_sendonly_domain', 'default_information_level',
                   'default_information_level6', 'default_information_metric', 'default_information_metric6',
                   'default_information_originate', 'default_information_originate6', 'ignore_attached_bit',
                   'interface', 'is_type', 'log_neighbour_changes',
                   'lsp_gen_interval_l1', 'lsp_gen_interval_l2', 'lsp_refresh_interval',
                   'max_lsp_lifetime', 'metric_style', 'net',
                   'overload_bit', 'redistribute', 'redistribute_l1',
                   'redistribute_l1_list', 'redistribute6', 'redistribute6_l1',
                   'redistribute6_l1_list', 'router_id', 'spf_interval_exp_l1',
                   'spf_interval_exp_l2', 'summary_address', 'summary_address6']

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


def router_isis(data, fos):
    router_isis_data = data['router_isis']
    filtered_data = underscore_to_hyphen(filter_router_isis_data(router_isis_data))

    return fos.set('router',
                   'isis',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_router(data, fos):
    fos.do_member_operation('router', 'isis')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['router_isis']:
        resp = router_isis(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('router_isis'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
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
    "type": "dict",
    "children": {
        "default_information_metric6": {
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
            "name": "default_information_metric6",
            "help": "Default ipv6 route metric.",
            "category": "unitary"
        },
        "auth_sendonly_domain": {
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
            "options": [
                {
                    "value": "enable",
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
                    }
                },
                {
                    "value": "disable",
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
                    }
                }
            ],
            "name": "auth_sendonly_domain",
            "help": "Enable authentication send-only for level 2 SNP PDUs.",
            "category": "unitary"
        },
        "default_information_originate6": {
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
            "options": [
                {
                    "value": "enable",
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
                    }
                },
                {
                    "value": "always",
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
                    }
                },
                {
                    "value": "disable",
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
                    }
                }
            ],
            "name": "default_information_originate6",
            "help": "Enable/disable generation of default ipv6 route.",
            "category": "unitary"
        },
        "summary_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "prefix": {
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
                    "name": "prefix",
                    "help": "prefix.",
                    "category": "unitary"
                },
                "id": {
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
                    "name": "id",
                    "help": "Summary address entry id.",
                    "category": "unitary"
                },
                "level": {
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
                    "options": [
                        {
                            "value": "level_1_2",
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
                            }
                        },
                        {
                            "value": "level_1",
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
                            }
                        },
                        {
                            "value": "level_2",
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
                            }
                        }
                    ],
                    "name": "level",
                    "help": "Level.",
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
            "name": "summary_address",
            "help": "IS-IS summary addresses.",
            "mkey": "id",
            "category": "table"
        },
        "metric_style": {
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
            "options": [
                {
                    "value": "narrow",
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
                    }
                },
                {
                    "value": "wide",
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
                    }
                },
                {
                    "value": "transition",
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
                    }
                }
            ],
            "name": "metric_style",
            "help": "Use old-style (ISO 10589) or new-style packet formats.",
            "category": "unitary"
        },
        "redistribute6_l1": {
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
            "options": [
                {
                    "value": "enable",
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
                    }
                },
                {
                    "value": "disable",
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
                    }
                }
            ],
            "name": "redistribute6_l1",
            "help": "Redistribute level 1 v6 routes into level 2.",
            "category": "unitary"
        },
        "lsp_refresh_interval": {
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
            "name": "lsp_refresh_interval",
            "help": "LSP refresh time in seconds.",
            "category": "unitary"
        },
        "max_lsp_lifetime": {
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
            "name": "max_lsp_lifetime",
            "help": "Maximum LSP lifetime in seconds.",
            "category": "unitary"
        },
        "ignore_attached_bit": {
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
            "options": [
                {
                    "value": "enable",
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
                    }
                },
                {
                    "value": "disable",
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
                    }
                }
            ],
            "name": "ignore_attached_bit",
            "help": "Ignore Attached bit on incoming L1 LSP.",
            "category": "unitary"
        },
        "redistribute6_l1_list": {
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
            "name": "redistribute6_l1_list",
            "help": "Access-list for redistribute v6 routes from l1 to l2.",
            "category": "unitary"
        },
        "auth_keychain_area": {
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
            "name": "auth_keychain_area",
            "help": "IS-IS area authentication key-chain. Applicable when area's auth mode is md5.",
            "category": "unitary"
        },
        "auth_mode_area": {
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
            "options": [
                {
                    "value": "password",
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
                    }
                },
                {
                    "value": "md5",
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
                    }
                }
            ],
            "name": "auth_mode_area",
            "help": "IS-IS area(level-1) authentication mode.",
            "category": "unitary"
        },
        "default_information_level": {
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
            "options": [
                {
                    "value": "level_1_2",
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
                    }
                },
                {
                    "value": "level_1",
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
                    }
                },
                {
                    "value": "level_2",
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
                    }
                }
            ],
            "name": "default_information_level",
            "help": "Distribute default route into level's LSP.",
            "category": "unitary"
        },
        "redistribute_l1": {
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
            "options": [
                {
                    "value": "enable",
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
                    }
                },
                {
                    "value": "disable",
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
                    }
                }
            ],
            "name": "redistribute_l1",
            "help": "Redistribute level 1 routes into level 2.",
            "category": "unitary"
        },
        "net": {
            "type": "list",
            "elements": "dict",
            "children": {
                "net": {
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
                    "name": "net",
                    "help": "isis net xx.xxxx. ... .xxxx.xx",
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
            "name": "net",
            "help": "IS-IS net configuration.",
            "category": "table"
        },
        "summary_address6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "level": {
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
                    "options": [
                        {
                            "value": "level_1_2",
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
                            }
                        },
                        {
                            "value": "level_1",
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
                            }
                        },
                        {
                            "value": "level_2",
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
                            }
                        }
                    ],
                    "name": "level",
                    "help": "Level.",
                    "category": "unitary"
                },
                "prefix6": {
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
                    "name": "prefix6",
                    "help": "IPv6 prefix",
                    "category": "unitary"
                },
                "id": {
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
                    "name": "id",
                    "help": "Summary address entry id.",
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
            "name": "summary_address6",
            "help": "IS-IS summary ipv6 addresses.",
            "mkey": "id",
            "category": "table"
        },
        "auth_mode_domain": {
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
            "options": [
                {
                    "value": "password",
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
                    }
                },
                {
                    "value": "md5",
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
                    }
                }
            ],
            "name": "auth_mode_domain",
            "help": "ISIS domain(level-2) authentication mode.",
            "category": "unitary"
        },
        "lsp_gen_interval_l1": {
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
            "name": "lsp_gen_interval_l1",
            "help": "Minimum interval for level 1 LSP regenerating.",
            "category": "unitary"
        },
        "lsp_gen_interval_l2": {
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
            "name": "lsp_gen_interval_l2",
            "help": "Minimum interval for level 2 LSP regenerating.",
            "category": "unitary"
        },
        "redistribute_l1_list": {
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
            "name": "redistribute_l1_list",
            "help": "Access-list for redistribute l1 to l2.",
            "category": "unitary"
        },
        "overload_bit": {
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
            "options": [
                {
                    "value": "enable",
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
                    }
                },
                {
                    "value": "disable",
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
                    }
                }
            ],
            "name": "overload_bit",
            "help": "Signal other routers not to use us in SPF.",
            "category": "unitary"
        },
        "auth_password_area": {
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
            "name": "auth_password_area",
            "help": "IS-IS area(level-1) authentication password. Applicable when area's auth mode is password.",
            "category": "unitary"
        },
        "default_information_metric": {
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
            "name": "default_information_metric",
            "help": "Default information metric.",
            "category": "unitary"
        },
        "default_information_originate": {
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
            "options": [
                {
                    "value": "enable",
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
                    }
                },
                {
                    "value": "always",
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
                    }
                },
                {
                    "value": "disable",
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
                    }
                }
            ],
            "name": "default_information_originate",
            "help": "Enable/disable generation of default route.",
            "category": "unitary"
        },
        "interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "auth_password_hello": {
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
                    "name": "auth_password_hello",
                    "help": "Hello PDU authentication password. Applicable when hello's auth mode is password.",
                    "category": "unitary"
                },
                "priority_l2": {
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
                    "name": "priority_l2",
                    "help": "Level 2 priority.",
                    "category": "unitary"
                },
                "priority_l1": {
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
                    "name": "priority_l1",
                    "help": "Level 1 priority.",
                    "category": "unitary"
                },
                "hello_multiplier_l2": {
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
                    "name": "hello_multiplier_l2",
                    "help": "Level 2 multiplier for Hello holding time.",
                    "category": "unitary"
                },
                "hello_multiplier_l1": {
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
                    "name": "hello_multiplier_l1",
                    "help": "Level 1 multiplier for Hello holding time.",
                    "category": "unitary"
                },
                "auth_mode_hello": {
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
                    "options": [
                        {
                            "value": "md5",
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
                            }
                        },
                        {
                            "value": "password",
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
                            }
                        }
                    ],
                    "name": "auth_mode_hello",
                    "help": "Hello PDU authentication mode.",
                    "category": "unitary"
                },
                "bfd": {
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
                    "options": [
                        {
                            "value": "enable",
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
                            }
                        },
                        {
                            "value": "disable",
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
                            }
                        }
                    ],
                    "name": "bfd",
                    "help": "Bidirectional Forwarding Detection (BFD).",
                    "category": "unitary"
                },
                "passive": {
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
                    "options": [
                        {
                            "value": "enable",
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
                            }
                        },
                        {
                            "value": "disable",
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
                            }
                        }
                    ],
                    "name": "passive",
                    "help": "Set this interface as passive.",
                    "category": "unitary"
                },
                "circuit_type": {
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
                    "options": [
                        {
                            "value": "level_1_2",
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
                            }
                        },
                        {
                            "value": "level_1",
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
                            }
                        },
                        {
                            "value": "level_2",
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
                            }
                        }
                    ],
                    "name": "circuit_type",
                    "help": "IS-IS interface's circuit type.",
                    "category": "unitary"
                },
                "bfd6": {
                    "revisions": {
                        "v7.0.0": True,
                        "v7.0.1": True,
                        "v7.0.2": True,
                        "v7.0.3": True,
                        "v7.0.4": True,
                        "v7.0.5": True,
                        "v7.0.6": True,
                        "v7.2.1": True,
                        "v7.2.2": False,
                        "v7.2.3": False,
                        "v7.2.4": False,
                        "v7.2.5": False,
                        "v7.4.0": False
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v7.0.1": True,
                                "v7.0.2": True,
                                "v7.0.3": True,
                                "v7.0.4": True,
                                "v7.0.5": True,
                                "v7.0.6": True,
                                "v7.2.1": True
                            }
                        }
                    ],
                    "name": "bfd6",
                    "help": "Ipv6 Bidirectional Forwarding Detection (BFD).",
                    "category": "unitary"
                },
                "wide_metric_l1": {
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
                    "name": "wide_metric_l1",
                    "help": "Level 1 wide metric for interface.",
                    "category": "unitary"
                },
                "wide_metric_l2": {
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
                    "name": "wide_metric_l2",
                    "help": "Level 2 wide metric for interface.",
                    "category": "unitary"
                },
                "status": {
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
                    "options": [
                        {
                            "value": "enable",
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
                            }
                        },
                        {
                            "value": "disable",
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
                            }
                        }
                    ],
                    "name": "status",
                    "help": "Enable the interface for IS-IS.",
                    "category": "unitary"
                },
                "metric_l1": {
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
                    "name": "metric_l1",
                    "help": "Level 1 metric for interface.",
                    "category": "unitary"
                },
                "metric_l2": {
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
                    "name": "metric_l2",
                    "help": "Level 2 metric for interface.",
                    "category": "unitary"
                },
                "status6": {
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
                    "options": [
                        {
                            "value": "enable",
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
                            }
                        },
                        {
                            "value": "disable",
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
                            }
                        }
                    ],
                    "name": "status6",
                    "help": "Enable/disable interface for ipv6 IS-IS.",
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
                    "help": "IS-IS interface name",
                    "category": "unitary"
                },
                "auth_keychain_hello": {
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
                    "name": "auth_keychain_hello",
                    "help": "Hello PDU authentication key-chain. Applicable when hello's auth mode is md5.",
                    "category": "unitary"
                },
                "hello_interval_l2": {
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
                    "name": "hello_interval_l2",
                    "help": "Level 2 hello interval.",
                    "category": "unitary"
                },
                "csnp_interval_l2": {
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
                    "name": "csnp_interval_l2",
                    "help": "Level 2 CSNP interval.",
                    "category": "unitary"
                },
                "csnp_interval_l1": {
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
                    "name": "csnp_interval_l1",
                    "help": "Level 1 CSNP interval.",
                    "category": "unitary"
                },
                "hello_padding": {
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
                    "options": [
                        {
                            "value": "enable",
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
                            }
                        },
                        {
                            "value": "disable",
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
                            }
                        }
                    ],
                    "name": "hello_padding",
                    "help": "Enable padding to IS-IS hello packets.",
                    "category": "unitary"
                },
                "hello_interval_l1": {
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
                    "name": "hello_interval_l1",
                    "help": "Level 1 hello interval.",
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
            "name": "interface",
            "help": "IS-IS interface configuration.",
            "mkey": "name",
            "category": "table"
        },
        "auth_keychain_domain": {
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
            "name": "auth_keychain_domain",
            "help": "IS-IS domain authentication key-chain. Applicable when domain's auth mode is md5.",
            "category": "unitary"
        },
        "spf_interval_exp_l2": {
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
            "name": "spf_interval_exp_l2",
            "help": "Level 2 SPF minimum calculation delay in secs.",
            "category": "unitary"
        },
        "spf_interval_exp_l1": {
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
            "name": "spf_interval_exp_l1",
            "help": "Level 1 SPF minimum calculation delay in secs.",
            "category": "unitary"
        },
        "auth_password_domain": {
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
            "name": "auth_password_domain",
            "help": "IS-IS domain(level-2) authentication password. Applicable when domain's auth mode is password.",
            "category": "unitary"
        },
        "redistribute": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
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
                    "options": [
                        {
                            "value": "enable",
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
                            }
                        },
                        {
                            "value": "disable",
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
                            }
                        }
                    ],
                    "name": "status",
                    "help": "status.",
                    "category": "unitary"
                },
                "protocol": {
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
                    "name": "protocol",
                    "help": "protocol name.",
                    "category": "unitary"
                },
                "level": {
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
                    "options": [
                        {
                            "value": "level_1_2",
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
                            }
                        },
                        {
                            "value": "level_1",
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
                            }
                        },
                        {
                            "value": "level_2",
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
                            }
                        }
                    ],
                    "name": "level",
                    "help": "level.",
                    "category": "unitary"
                },
                "metric": {
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
                    "name": "metric",
                    "help": "metric.",
                    "category": "unitary"
                },
                "routemap": {
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
                    "name": "routemap",
                    "help": "routemap name.",
                    "category": "unitary"
                },
                "metric_type": {
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
                    "options": [
                        {
                            "value": "external",
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
                            }
                        },
                        {
                            "value": "internal",
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
                            }
                        }
                    ],
                    "name": "metric_type",
                    "help": "metric type.",
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
            "name": "redistribute",
            "help": "IS-IS redistribute protocols.",
            "mkey": "protocol",
            "category": "table"
        },
        "router_id": {
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
            "name": "router_id",
            "help": "Router ID.",
            "category": "unitary"
        },
        "auth_sendonly_area": {
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
            "options": [
                {
                    "value": "enable",
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
                    }
                },
                {
                    "value": "disable",
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
                    }
                }
            ],
            "name": "auth_sendonly_area",
            "help": "Enable authentication send-only for level 1 SNP PDUs.",
            "category": "unitary"
        },
        "is_type": {
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
            "options": [
                {
                    "value": "level_1_2",
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
                    }
                },
                {
                    "value": "level_1",
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
                    }
                },
                {
                    "value": "level_2_only",
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
                    }
                }
            ],
            "name": "is_type",
            "help": "IS-type.",
            "category": "unitary"
        },
        "default_information_level6": {
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
            "options": [
                {
                    "value": "level_1_2",
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
                    }
                },
                {
                    "value": "level_1",
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
                    }
                },
                {
                    "value": "level_2",
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
                    }
                }
            ],
            "name": "default_information_level6",
            "help": "Distribute ipv6 default route into level's LSP.",
            "category": "unitary"
        },
        "redistribute6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
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
                    "options": [
                        {
                            "value": "enable",
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
                            }
                        },
                        {
                            "value": "disable",
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
                            }
                        }
                    ],
                    "name": "status",
                    "help": "status.",
                    "category": "unitary"
                },
                "metric": {
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
                    "name": "metric",
                    "help": "metric.",
                    "category": "unitary"
                },
                "routemap": {
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
                    "name": "routemap",
                    "help": "routemap name.",
                    "category": "unitary"
                },
                "protocol": {
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
                    "name": "protocol",
                    "help": "protocol name.",
                    "category": "unitary"
                },
                "level": {
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
                    "options": [
                        {
                            "value": "level_1_2",
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
                            }
                        },
                        {
                            "value": "level_1",
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
                            }
                        },
                        {
                            "value": "level_2",
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
                            }
                        }
                    ],
                    "name": "level",
                    "help": "level.",
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
            "name": "redistribute6",
            "help": "IS-IS redistribute v6 protocols.",
            "mkey": "protocol",
            "category": "table"
        },
        "log_neighbour_changes": {
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
            "options": [
                {
                    "value": "enable",
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
                    }
                },
                {
                    "value": "disable",
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
                    }
                }
            ],
            "name": "log_neighbour_changes",
            "help": "Enable logging of ISIS neighbour's changes",
            "category": "unitary"
        }
    },
    "name": "isis",
    "help": "ISIS configuration.",
    "category": "complex"
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
        "router_isis": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["router_isis"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["router_isis"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "router_isis")
        is_error, has_changed, result, diff = fortiswitch_router(module.params, fos)
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
