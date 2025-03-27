#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
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
    - ansible>=2.15
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
                    - 'level-1-2'
                    - 'level-1'
                    - 'level-2'
            default_information_level6:
                description:
                    - Distribute ipv6 default route into level"s LSP.
                type: str
                choices:
                    - 'level-1-2'
                    - 'level-1'
                    - 'level-2'
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
                            - 'level-1-2'
                            - 'level-1'
                            - 'level-2'
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
                    - 'level-1-2'
                    - 'level-1'
                    - 'level-2-only'
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
                    id:
                        description:
                            - ISIS net ID
                        type: int
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
                            - 'level-1-2'
                            - 'level-1'
                            - 'level-2'
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
                            - 'level-1-2'
                            - 'level-1'
                            - 'level-2'
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
                            - 'level-1-2'
                            - 'level-1'
                            - 'level-2'
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
                            - 'level-1-2'
                            - 'level-1'
                            - 'level-2'
                    prefix6:
                        description:
                            - IPv6 prefix
                        type: str
"""

EXAMPLES = """
- name: ISIS configuration.
  fortinet.fortiswitch.fortiswitch_router_isis:
      router_isis:
          auth_keychain_area: "<your_own_value> (source router.key-chain.name)"
          auth_keychain_domain: "<your_own_value> (source router.key-chain.name)"
          auth_mode_area: "password"
          auth_mode_domain: "password"
          auth_password_area: "<your_own_value>"
          auth_password_domain: "<your_own_value>"
          auth_sendonly_area: "enable"
          auth_sendonly_domain: "enable"
          default_information_level: "level-1-2"
          default_information_level6: "level-1-2"
          default_information_metric: "8388607"
          default_information_metric6: "8388607"
          default_information_originate: "enable"
          default_information_originate6: "enable"
          ignore_attached_bit: "enable"
          interface:
              -
                  auth_keychain_hello: "<your_own_value> (source router.key-chain.name)"
                  auth_mode_hello: "md5"
                  auth_password_hello: "<your_own_value>"
                  bfd: "enable"
                  bfd6: "enable"
                  circuit_type: "level-1-2"
                  csnp_interval_l1: "32767"
                  csnp_interval_l2: "32767"
                  hello_interval_l1: "32767"
                  hello_interval_l2: "32767"
                  hello_multiplier_l1: "50"
                  hello_multiplier_l2: "50"
                  hello_padding: "enable"
                  metric_l1: "31"
                  metric_l2: "31"
                  name: "default_name_34 (source system.interface.name)"
                  passive: "enable"
                  priority_l1: "63"
                  priority_l2: "63"
                  status: "enable"
                  status6: "enable"
                  wide_metric_l1: "8388607"
                  wide_metric_l2: "8388607"
          is_type: "level-1-2"
          log_neighbour_changes: "enable"
          lsp_gen_interval_l1: "60"
          lsp_gen_interval_l2: "60"
          lsp_refresh_interval: "32767"
          max_lsp_lifetime: "32767"
          metric_style: "narrow"
          net:
              -
                  id: "50"
                  net: "<your_own_value>"
          overload_bit: "enable"
          redistribute:
              -
                  level: "level-1-2"
                  metric: "2130706432"
                  metric_type: "external"
                  protocol: "<your_own_value>"
                  routemap: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          redistribute6:
              -
                  level: "level-1-2"
                  metric: "2130706432"
                  protocol: "<your_own_value>"
                  routemap: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          redistribute6_l1: "enable"
          redistribute6_l1_list: "<your_own_value> (source router.access-list6.name)"
          redistribute_l1: "enable"
          redistribute_l1_list: "<your_own_value> (source router.access-list.name)"
          router_id: "<your_own_value>"
          spf_interval_exp_l1: "60"
          spf_interval_exp_l2: "60"
          summary_address:
              -
                  id: "74"
                  level: "level-1-2"
                  prefix: "<your_own_value>"
          summary_address6:
              -
                  id: "78"
                  level: "level-1-2"
                  prefix6: "<your_own_value>"
"""

RETURN = """
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

"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import (
    find_current_values,
)


def filter_router_isis_data(json):
    option_list = [
        "auth_keychain_area",
        "auth_keychain_domain",
        "auth_mode_area",
        "auth_mode_domain",
        "auth_password_area",
        "auth_password_domain",
        "auth_sendonly_area",
        "auth_sendonly_domain",
        "default_information_level",
        "default_information_level6",
        "default_information_metric",
        "default_information_metric6",
        "default_information_originate",
        "default_information_originate6",
        "ignore_attached_bit",
        "interface",
        "is_type",
        "log_neighbour_changes",
        "lsp_gen_interval_l1",
        "lsp_gen_interval_l2",
        "lsp_refresh_interval",
        "max_lsp_lifetime",
        "metric_style",
        "net",
        "overload_bit",
        "redistribute",
        "redistribute6",
        "redistribute6_l1",
        "redistribute6_l1_list",
        "redistribute_l1",
        "redistribute_l1_list",
        "router_id",
        "spf_interval_exp_l1",
        "spf_interval_exp_l2",
        "summary_address",
        "summary_address6",
    ]

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
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data


def router_isis(data, fos, check_mode=False):
    state = data.get("state", None)

    router_isis_data = data["router_isis"]

    filtered_data = filter_router_isis_data(router_isis_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("router", "isis", filtered_data)
        current_data = fos.get("router", "isis", mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and isinstance(current_data.get("results"), list)
            and len(current_data["results"]) > 0
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            mkeyname = fos.get_mkeyname(None, None)
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)

            # handle global modules'
            if mkeyname is None and state is None:
                is_same = is_same_comparison(
                    serialize(current_data["results"]), serialize(copied_filtered_data)
                )

                current_values = find_current_values(
                    copied_filtered_data, current_data["results"]
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": copied_filtered_data},
                )

            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]),
                    serialize(copied_filtered_data),
                )

                current_values = find_current_values(
                    copied_filtered_data, current_data["results"][0]
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": copied_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}

    return fos.set(
        "router",
        "isis",
        data=filtered_data,
    )


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortiswitch_router(data, fos, check_mode):
    fos.do_member_operation("router", "isis")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["router_isis"]:
        resp = router_isis(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_isis"))
    if check_mode:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp) and current_cmdb_index != resp["cmdb-index"],
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v7.0.0", ""]],
    "type": "dict",
    "children": {
        "default_information_metric6": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "default-information-metric6",
            "help": "Default ipv6 route metric.",
            "category": "unitary",
        },
        "auth_sendonly_domain": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "auth-sendonly-domain",
            "help": "Enable authentication send-only for level 2 SNP PDUs.",
            "category": "unitary",
        },
        "default_information_originate6": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "always"}, {"value": "disable"}],
            "name": "default-information-originate6",
            "help": "Enable/disable generation of default ipv6 route.",
            "category": "unitary",
        },
        "summary_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "prefix": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "prefix",
                    "help": "prefix.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Summary address entry id.",
                    "category": "unitary",
                },
                "level": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "level-1-2"},
                        {"value": "level-1"},
                        {"value": "level-2"},
                    ],
                    "name": "level",
                    "help": "Level.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "summary-address",
            "help": "IS-IS summary addresses.",
            "mkey": "id",
            "category": "table",
        },
        "metric_style": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "narrow"},
                {"value": "wide"},
                {"value": "transition"},
            ],
            "name": "metric-style",
            "help": "Use old-style (ISO 10589) or new-style packet formats.",
            "category": "unitary",
        },
        "redistribute6_l1": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "redistribute6-l1",
            "help": "Redistribute level 1 v6 routes into level 2.",
            "category": "unitary",
        },
        "lsp_refresh_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "lsp-refresh-interval",
            "help": "LSP refresh time in seconds.",
            "category": "unitary",
        },
        "max_lsp_lifetime": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "max-lsp-lifetime",
            "help": "Maximum LSP lifetime in seconds.",
            "category": "unitary",
        },
        "ignore_attached_bit": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "ignore-attached-bit",
            "help": "Ignore Attached bit on incoming L1 LSP.",
            "category": "unitary",
        },
        "redistribute6_l1_list": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "redistribute6-l1-list",
            "help": "Access-list for redistribute v6 routes from l1 to l2.",
            "category": "unitary",
        },
        "auth_keychain_area": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "auth-keychain-area",
            "help": "IS-IS area authentication key-chain. Applicable when area's auth mode is md5.",
            "category": "unitary",
        },
        "auth_mode_area": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "password"}, {"value": "md5"}],
            "name": "auth-mode-area",
            "help": "IS-IS area(level-1) authentication mode.",
            "category": "unitary",
        },
        "default_information_level": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "level-1-2"},
                {"value": "level-1"},
                {"value": "level-2"},
            ],
            "name": "default-information-level",
            "help": "Distribute default route into level's LSP.",
            "category": "unitary",
        },
        "redistribute_l1": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "redistribute-l1",
            "help": "Redistribute level 1 routes into level 2.",
            "category": "unitary",
        },
        "net": {
            "type": "list",
            "elements": "dict",
            "children": {
                "net": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "net",
                    "help": "isis net xx.xxxx. ... .xxxx.xx",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "ISIS net ID",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "net",
            "help": "IS-IS net configuration.",
            "mkey": "id",
            "category": "table",
        },
        "summary_address6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "level": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "level-1-2"},
                        {"value": "level-1"},
                        {"value": "level-2"},
                    ],
                    "name": "level",
                    "help": "Level.",
                    "category": "unitary",
                },
                "prefix6": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "prefix6",
                    "help": "IPv6 prefix",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Summary address entry id.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "summary-address6",
            "help": "IS-IS summary ipv6 addresses.",
            "mkey": "id",
            "category": "table",
        },
        "auth_mode_domain": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "password"}, {"value": "md5"}],
            "name": "auth-mode-domain",
            "help": "ISIS domain(level-2) authentication mode.",
            "category": "unitary",
        },
        "lsp_gen_interval_l1": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "lsp-gen-interval-l1",
            "help": "Minimum interval for level 1 LSP regenerating.",
            "category": "unitary",
        },
        "lsp_gen_interval_l2": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "lsp-gen-interval-l2",
            "help": "Minimum interval for level 2 LSP regenerating.",
            "category": "unitary",
        },
        "redistribute_l1_list": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "redistribute-l1-list",
            "help": "Access-list for redistribute l1 to l2.",
            "category": "unitary",
        },
        "overload_bit": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "overload-bit",
            "help": "Signal other routers not to use us in SPF.",
            "category": "unitary",
        },
        "auth_password_area": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "auth-password-area",
            "help": "IS-IS area(level-1) authentication password. Applicable when area's auth mode is password.",
            "category": "unitary",
        },
        "default_information_metric": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "default-information-metric",
            "help": "Default information metric.",
            "category": "unitary",
        },
        "default_information_originate": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "always"}, {"value": "disable"}],
            "name": "default-information-originate",
            "help": "Enable/disable generation of default route.",
            "category": "unitary",
        },
        "interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "auth_password_hello": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "auth-password-hello",
                    "help": "Hello PDU authentication password. Applicable when hello's auth mode is password.",
                    "category": "unitary",
                },
                "priority_l2": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "priority-l2",
                    "help": "Level 2 priority.",
                    "category": "unitary",
                },
                "priority_l1": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "priority-l1",
                    "help": "Level 1 priority.",
                    "category": "unitary",
                },
                "hello_multiplier_l2": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "hello-multiplier-l2",
                    "help": "Level 2 multiplier for Hello holding time.",
                    "category": "unitary",
                },
                "hello_multiplier_l1": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "hello-multiplier-l1",
                    "help": "Level 1 multiplier for Hello holding time.",
                    "category": "unitary",
                },
                "auth_mode_hello": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "md5"}, {"value": "password"}],
                    "name": "auth-mode-hello",
                    "help": "Hello PDU authentication mode.",
                    "category": "unitary",
                },
                "bfd": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "bfd",
                    "help": "Bidirectional Forwarding Detection (BFD).",
                    "category": "unitary",
                },
                "passive": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "passive",
                    "help": "Set this interface as passive.",
                    "category": "unitary",
                },
                "circuit_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "level-1-2"},
                        {"value": "level-1"},
                        {"value": "level-2"},
                    ],
                    "name": "circuit-type",
                    "help": "IS-IS interface's circuit type.",
                    "category": "unitary",
                },
                "bfd6": {
                    "v_range": [["v7.0.0", "v7.2.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "bfd6",
                    "help": "Ipv6 Bidirectional Forwarding Detection (BFD).",
                    "category": "unitary",
                },
                "wide_metric_l1": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "wide-metric-l1",
                    "help": "Level 1 wide metric for interface.",
                    "category": "unitary",
                },
                "wide_metric_l2": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "wide-metric-l2",
                    "help": "Level 2 wide metric for interface.",
                    "category": "unitary",
                },
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "status",
                    "help": "Enable the interface for IS-IS.",
                    "category": "unitary",
                },
                "metric_l1": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "metric-l1",
                    "help": "Level 1 metric for interface.",
                    "category": "unitary",
                },
                "metric_l2": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "metric-l2",
                    "help": "Level 2 metric for interface.",
                    "category": "unitary",
                },
                "status6": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "status6",
                    "help": "Enable/disable interface for ipv6 IS-IS.",
                    "category": "unitary",
                },
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "IS-IS interface name",
                    "category": "unitary",
                },
                "auth_keychain_hello": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "auth-keychain-hello",
                    "help": "Hello PDU authentication key-chain. Applicable when hello's auth mode is md5.",
                    "category": "unitary",
                },
                "hello_interval_l2": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "hello-interval-l2",
                    "help": "Level 2 hello interval.",
                    "category": "unitary",
                },
                "csnp_interval_l2": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "csnp-interval-l2",
                    "help": "Level 2 CSNP interval.",
                    "category": "unitary",
                },
                "csnp_interval_l1": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "csnp-interval-l1",
                    "help": "Level 1 CSNP interval.",
                    "category": "unitary",
                },
                "hello_padding": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "hello-padding",
                    "help": "Enable padding to IS-IS hello packets.",
                    "category": "unitary",
                },
                "hello_interval_l1": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "hello-interval-l1",
                    "help": "Level 1 hello interval.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "interface",
            "help": "IS-IS interface configuration.",
            "mkey": "name",
            "category": "table",
        },
        "auth_keychain_domain": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "auth-keychain-domain",
            "help": "IS-IS domain authentication key-chain. Applicable when domain's auth mode is md5.",
            "category": "unitary",
        },
        "spf_interval_exp_l2": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "spf-interval-exp-l2",
            "help": "Level 2 SPF minimum calculation delay in secs.",
            "category": "unitary",
        },
        "spf_interval_exp_l1": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "spf-interval-exp-l1",
            "help": "Level 1 SPF minimum calculation delay in secs.",
            "category": "unitary",
        },
        "auth_password_domain": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "auth-password-domain",
            "help": "IS-IS domain(level-2) authentication password. Applicable when domain's auth mode is password.",
            "category": "unitary",
        },
        "redistribute": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "status",
                    "help": "status.",
                    "category": "unitary",
                },
                "protocol": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "protocol",
                    "help": "protocol name.",
                    "category": "unitary",
                },
                "level": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "level-1-2"},
                        {"value": "level-1"},
                        {"value": "level-2"},
                    ],
                    "name": "level",
                    "help": "level.",
                    "category": "unitary",
                },
                "metric": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "metric",
                    "help": "metric.",
                    "category": "unitary",
                },
                "routemap": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "routemap",
                    "help": "routemap name.",
                    "category": "unitary",
                },
                "metric_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "external"}, {"value": "internal"}],
                    "name": "metric-type",
                    "help": "metric type.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "redistribute",
            "help": "IS-IS redistribute protocols.",
            "mkey": "protocol",
            "category": "table",
        },
        "router_id": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "router-id",
            "help": "Router ID.",
            "category": "unitary",
        },
        "auth_sendonly_area": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "auth-sendonly-area",
            "help": "Enable authentication send-only for level 1 SNP PDUs.",
            "category": "unitary",
        },
        "is_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "level-1-2"},
                {"value": "level-1"},
                {"value": "level-2-only"},
            ],
            "name": "is-type",
            "help": "IS-type.",
            "category": "unitary",
        },
        "default_information_level6": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "level-1-2"},
                {"value": "level-1"},
                {"value": "level-2"},
            ],
            "name": "default-information-level6",
            "help": "Distribute ipv6 default route into level's LSP.",
            "category": "unitary",
        },
        "redistribute6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                    "name": "status",
                    "help": "status.",
                    "category": "unitary",
                },
                "metric": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "metric",
                    "help": "metric.",
                    "category": "unitary",
                },
                "routemap": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "routemap",
                    "help": "routemap name.",
                    "category": "unitary",
                },
                "protocol": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "protocol",
                    "help": "protocol name.",
                    "category": "unitary",
                },
                "level": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "level-1-2"},
                        {"value": "level-1"},
                        {"value": "level-2"},
                    ],
                    "name": "level",
                    "help": "level.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "redistribute6",
            "help": "IS-IS redistribute v6 protocols.",
            "mkey": "protocol",
            "category": "table",
        },
        "log_neighbour_changes": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "log-neighbour-changes",
            "help": "Enable logging of ISIS neighbour's changes",
            "category": "unitary",
        },
    },
    "name": "isis",
    "help": "ISIS configuration.",
    "category": "complex",
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = versioned_schema["mkey"] if "mkey" in versioned_schema else None
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "router_isis": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_isis"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_isis"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "router_isis"
        )
        is_error, has_changed, result, diff = fortiswitch_router(
            module.params, fos, module.check_mode
        )
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortiSwitch system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
