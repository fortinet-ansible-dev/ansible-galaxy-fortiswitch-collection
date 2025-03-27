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
module: fortiswitch_export_config_playbook
version_added: "1.0.0"
short_description: Collect the current configurations of the modules and convert then into playbooks.
description:
    - Collect the current configurations of a module on a running device and convert the returned facts into a playbook that users can apply directly.
    - More than one playbook will be generated if there are many selectors provided.
author:
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@fshen01)
notes:
    - Different selector may have different parameters, users are expected to look up them for a specific selector.
    - For some selectors, the objects are global, no params are allowed to appear.
    - If params is empty a non-unique object, the whole object list is returned.
    - This module has support for all configuration API, excluding any monitor API.
    - The result of API request is stored in results as a list.
requirements:
    - install galaxy collection fortinet.fortiswitch >= 1.0.0.
options:
    output_path:
        description:
            - the path used for saving the playbook.
        type: str
        required: true
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
            - A list of selectors used to fetch the current configurations and export the playbook.
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
                    - Module name that used to fetch the current configurations and export the playbook.
                type: str
                required: true
                choices:
                 - system_vdom
                 - system_global
                 - system.alias_command
                 - system.alias_group
                 - system_accprofile
                 - system_object-tag
                 - system_interface
                 - system_password-policy
                 - system_admin
                 - system_settings
                 - system_resource-limits
                 - system_vdom-property
                 - system_dns-database
                 - system_dns-server
                 - system_arp-table
                 - system_ipv6-neighbor-cache
                 - system_location
                 - system_dns
                 - system_sflow
                 - system_vdom-dns
                 - system.snmp_sysinfo
                 - system.snmp_community
                 - system.snmp_user
                 - system.autoupdate_override
                 - system.autoupdate_push-update
                 - system.autoupdate_schedule
                 - system.autoupdate_tunneling
                 - system.autoupdate_clientoverride
                 - system_session-ttl
                 - system.dhcp_server
                 - system_port-pair
                 - system_management-tunnel
                 - system_fortimanager
                 - system_fm
                 - system_central-management
                 - system_zone
                 - system.certificate_ca
                 - system.certificate_local
                 - system.certificate_crl
                 - system.certificate_remote
                 - system.certificate_ocsp
                 - system_fortianalyzer
                 - system_fortianalyzer2
                 - system_fortianalyzer3
                 - system_fortiguard
                 - system_fortiguard-log
                 - system_alertemail
                 - system_alarm
                 - system_mac-address-table
                 - system_proxy-arp
                 - system_tos-based-priority
                 - system_link-monitor
                 - system_console
                 - system_bug-report
                 - system_ntp
                 - system_fsw-cloud
                 - system_sniffer-profile
                 - system.schedule_onetime
                 - system.schedule_recurring
                 - system.schedule_group
                 - system_flow-export
                 - router_access-list6
                 - router_prefix-list6
                 - router_vrf
                 - router_aspath-list
                 - router_community-list
                 - router_access-list
                 - router_prefix-list
                 - router_route-map
                 - router_key-chain
                 - router_static
                 - router_policy
                 - router_rip
                 - router_ripng
                 - router_isis
                 - router_multicast-flow
                 - router_multicast
                 - router_static6
                 - router_ospf
                 - router_ospf6
                 - router_bgp
                 - router_auth-path
                 - router_setting
                 - router_gwdetect
                 - switch_domain
                 - switch_global
                 - switch.lldp_settings
                 - switch.lldp_profile
                 - switch.macsec_profile
                 - switch_vlan-tpid
                 - switch.qos_dot1p-map
                 - switch.qos_ip-dscp-map
                 - switch.qos_qos-policy
                 - switch.ptp_settings
                 - switch.ptp_policy
                 - switch_physical-port
                 - switch_vlan
                 - switch_trunk
                 - switch_raguard-policy
                 - switch_interface
                 - switch.stp_settings
                 - switch.stp_instance
                 - switch_static-mac
                 - switch_mirror
                 - switch_storm-control
                 - switch.acl_policer
                 - switch.acl_settings
                 - switch.acl.service_custom
                 - switch.acl_ingress
                 - switch.acl_egress
                 - switch.acl_prelookup
                 - switch_ip-mac-binding
                 - switch.igmp-snooping_globals
                 - switch.mld-snooping_globals
                 - switch_virtual-wire
                 - switch_security-feature
                 - switch_phy-mode
                 - switch_auto-isl-port-group
                 - switch_auto-network
                 - switch.network-monitor_settings
                 - switch.network-monitor_directed
                 - switch_quarantine
                 - user_radius
                 - user_tacacs+
                 - user_ldap
                 - user_local
                 - user_setting
                 - user_peer
                 - user_peergrp
                 - user_group
                 - log_custom-field
                 - log.syslogd_setting
                 - log.syslogd_override-setting
                 - log.syslogd_filter
                 - log.syslogd_override-filter
                 - log.syslogd2_setting
                 - log.syslogd2_filter
                 - log.syslogd3_setting
                 - log.syslogd3_filter
                 - log.memory_global-setting
                 - log.memory_setting
                 - log.memory_filter
                 - log.disk_setting
                 - log.disk_filter
                 - log_eventfilter
                 - log.fortiguard_setting
                 - log.remote_setting
                 - log_gui
                 - log.fortianalyzer_setting
                 - log.fortianalyzer_override-setting
                 - log.fortianalyzer_filter
                 - log.fortianalyzer_override-filter
                 - log.fortianalyzer2_setting
                 - log.fortianalyzer2_filter
                 - log.fortianalyzer3_setting
                 - log.fortianalyzer3_filter
                 - switch-controller_global
                 - alertemail_setting
                 - gui_console
                 - switch.acl_802-1X
                 - system_flan-cloud
                 - system_email-server
                 - system_vxlan
                 - system_web
                 - system_automation-trigger
                 - system_automation-action
                 - system_automation-destination
                 - system_automation-stitch
                 - system_auto-script
                 - system.ptp_profile
                 - system.ptp_interface-policy
                 - system_debug
                 - switch_vlan-pruning

    selector:
        description:
            - Module name that used to fetch the current configurations and export the playbook.
        type: str
        required: false
        choices:
         - system_vdom
         - system_global
         - system.alias_command
         - system.alias_group
         - system_accprofile
         - system_object-tag
         - system_interface
         - system_password-policy
         - system_admin
         - system_settings
         - system_resource-limits
         - system_vdom-property
         - system_dns-database
         - system_dns-server
         - system_arp-table
         - system_ipv6-neighbor-cache
         - system_location
         - system_dns
         - system_sflow
         - system_vdom-dns
         - system.snmp_sysinfo
         - system.snmp_community
         - system.snmp_user
         - system.autoupdate_override
         - system.autoupdate_push-update
         - system.autoupdate_schedule
         - system.autoupdate_tunneling
         - system.autoupdate_clientoverride
         - system_session-ttl
         - system.dhcp_server
         - system_port-pair
         - system_management-tunnel
         - system_fortimanager
         - system_fm
         - system_central-management
         - system_zone
         - system.certificate_ca
         - system.certificate_local
         - system.certificate_crl
         - system.certificate_remote
         - system.certificate_ocsp
         - system_fortianalyzer
         - system_fortianalyzer2
         - system_fortianalyzer3
         - system_fortiguard
         - system_fortiguard-log
         - system_alertemail
         - system_alarm
         - system_mac-address-table
         - system_proxy-arp
         - system_tos-based-priority
         - system_link-monitor
         - system_console
         - system_bug-report
         - system_ntp
         - system_fsw-cloud
         - system_sniffer-profile
         - system.schedule_onetime
         - system.schedule_recurring
         - system.schedule_group
         - system_flow-export
         - router_access-list6
         - router_prefix-list6
         - router_vrf
         - router_aspath-list
         - router_community-list
         - router_access-list
         - router_prefix-list
         - router_route-map
         - router_key-chain
         - router_static
         - router_policy
         - router_rip
         - router_ripng
         - router_isis
         - router_multicast-flow
         - router_multicast
         - router_static6
         - router_ospf
         - router_ospf6
         - router_bgp
         - router_auth-path
         - router_setting
         - router_gwdetect
         - switch_domain
         - switch_global
         - switch.lldp_settings
         - switch.lldp_profile
         - switch.macsec_profile
         - switch_vlan-tpid
         - switch.qos_dot1p-map
         - switch.qos_ip-dscp-map
         - switch.qos_qos-policy
         - switch.ptp_settings
         - switch.ptp_policy
         - switch_physical-port
         - switch_vlan
         - switch_trunk
         - switch_raguard-policy
         - switch_interface
         - switch.stp_settings
         - switch.stp_instance
         - switch_static-mac
         - switch_mirror
         - switch_storm-control
         - switch.acl_policer
         - switch.acl_settings
         - switch.acl.service_custom
         - switch.acl_ingress
         - switch.acl_egress
         - switch.acl_prelookup
         - switch_ip-mac-binding
         - switch.igmp-snooping_globals
         - switch.mld-snooping_globals
         - switch_virtual-wire
         - switch_security-feature
         - switch_phy-mode
         - switch_auto-isl-port-group
         - switch_auto-network
         - switch.network-monitor_settings
         - switch.network-monitor_directed
         - switch_quarantine
         - user_radius
         - user_tacacs+
         - user_ldap
         - user_local
         - user_setting
         - user_peer
         - user_peergrp
         - user_group
         - log_custom-field
         - log.syslogd_setting
         - log.syslogd_override-setting
         - log.syslogd_filter
         - log.syslogd_override-filter
         - log.syslogd2_setting
         - log.syslogd2_filter
         - log.syslogd3_setting
         - log.syslogd3_filter
         - log.memory_global-setting
         - log.memory_setting
         - log.memory_filter
         - log.disk_setting
         - log.disk_filter
         - log_eventfilter
         - log.fortiguard_setting
         - log.remote_setting
         - log_gui
         - log.fortianalyzer_setting
         - log.fortianalyzer_override-setting
         - log.fortianalyzer_filter
         - log.fortianalyzer_override-filter
         - log.fortianalyzer2_setting
         - log.fortianalyzer2_filter
         - log.fortianalyzer3_setting
         - log.fortianalyzer3_filter
         - switch-controller_global
         - alertemail_setting
         - gui_console
         - switch.acl_802-1X
         - system_flan-cloud
         - system_email-server
         - system_vxlan
         - system_web
         - system_automation-trigger
         - system_automation-action
         - system_automation-destination
         - system_automation-stitch
         - system_auto-script
         - system.ptp_profile
         - system.ptp_interface-policy
         - system_debug
         - switch_vlan-pruning

    params:
        description:
            - the parameter for each selector, see definition in above list.
        type: dict
        required: false
"""

EXAMPLES = """
- name: Will generate the playbooks for each selector/module.
  fortiswitch_export_config_playbook:
      selectors:
          - selector: system_interface
            params:
                name: "port1"
          - selector: system_ntp
      output_path: "./"
"""

RETURN = """
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
  sample: "interface"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "system"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FSVMEVYYQT3AB5352"
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
ansible_facts:
  description: The list of fact subsets collected from the device
  returned: always
  type: dict

"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)

MODULE_MKEY_DEFINITONS = {
    "system_vdom": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_global": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.alias_command": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.alias_group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_accprofile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_object-tag": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_interface": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_password-policy": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_admin": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_resource-limits": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_vdom-property": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_dns-database": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_dns-server": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_arp-table": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_ipv6-neighbor-cache": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_location": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_dns": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_sflow": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_vdom-dns": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.snmp_sysinfo": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.snmp_community": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system.snmp_user": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.autoupdate_override": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.autoupdate_push-update": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.autoupdate_schedule": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.autoupdate_tunneling": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.autoupdate_clientoverride": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_session-ttl": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.dhcp_server": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_port-pair": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_management-tunnel": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortimanager": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fm": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_central-management": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_zone": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.certificate_ca": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.certificate_local": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.certificate_crl": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.certificate_remote": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.certificate_ocsp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortianalyzer": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortianalyzer2": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortianalyzer3": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortiguard": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortiguard-log": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_alertemail": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_alarm": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_mac-address-table": {
        "mkey": "mac",
        "mkey_type": str,
    },
    "system_proxy-arp": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_tos-based-priority": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_link-monitor": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_console": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_bug-report": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ntp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fsw-cloud": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_sniffer-profile": {
        "mkey": "profile-name",
        "mkey_type": str,
    },
    "system.schedule_onetime": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.schedule_recurring": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.schedule_group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_flow-export": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_access-list6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_prefix-list6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_vrf": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_aspath-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_community-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_access-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_prefix-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_route-map": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_key-chain": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_static": {
        "mkey": "seq-num",
        "mkey_type": int,
    },
    "router_policy": {
        "mkey": "seq-num",
        "mkey_type": int,
    },
    "router_rip": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_ripng": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_isis": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_multicast-flow": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_multicast": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_static6": {
        "mkey": "seq-num",
        "mkey_type": int,
    },
    "router_ospf": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_ospf6": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_bgp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_auth-path": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_gwdetect": {
        "mkey": "interface",
        "mkey_type": str,
    },
    "switch_domain": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch_global": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch.lldp_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch.lldp_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch.macsec_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch_vlan-tpid": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch.qos_dot1p-map": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch.qos_ip-dscp-map": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch.qos_qos-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch.ptp_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch.ptp_policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch_physical-port": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch_vlan": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch_trunk": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch_raguard-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch_interface": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch.stp_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch.stp_instance": {
        "mkey": "id",
        "mkey_type": str,
    },
    "switch_static-mac": {
        "mkey": "seq-num",
        "mkey_type": int,
    },
    "switch_mirror": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch_storm-control": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch.acl_policer": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch.acl_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch.acl.service_custom": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch.acl_ingress": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch.acl_egress": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch.acl_prelookup": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch_ip-mac-binding": {
        "mkey": "seq-num",
        "mkey_type": int,
    },
    "switch.igmp-snooping_globals": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch.mld-snooping_globals": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch_virtual-wire": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch_security-feature": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch_phy-mode": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch_auto-isl-port-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch_auto-network": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch.network-monitor_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch.network-monitor_directed": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch_quarantine": {
        "mkey": "mac",
        "mkey_type": str,
    },
    "user_radius": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_tacacs+": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_ldap": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_local": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "user_peer": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_peergrp": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "log_custom-field": {
        "mkey": "id",
        "mkey_type": str,
    },
    "log.syslogd_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd2_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd2_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd3_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd3_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.memory_global-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.memory_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.memory_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.disk_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.disk_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log_eventfilter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortiguard_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.remote_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log_gui": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer2_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer2_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer3_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer3_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_global": {
        "mkey": "None",
        "mkey_type": None,
    },
    "alertemail_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "gui_console": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch.acl_802-1X": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_flan-cloud": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_email-server": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_vxlan": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_web": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_automation-trigger": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_automation-action": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_automation-destination": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_automation-stitch": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_auto-script": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.ptp_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.ptp_interface-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_debug": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch_vlan-pruning": {
        "mkey": "None",
        "mkey_type": None,
    },
}

SPECIAL_ATTRIBUTE_TABLE = {
    "system_interface": [
        ["allowaccess"],
        ["ipv6", "ip6_allowaccess"],
        ["secondaryip", "allowaccess"],
    ],
    "system_link_monitor": [["protocol"]],
}


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


def validate_mkey(params):
    selector = params["selector"]
    selector_params = params.get("params", {})

    if selector not in MODULE_MKEY_DEFINITONS:
        return False, {"message": "unknown selector: " + selector}

    definition = MODULE_MKEY_DEFINITONS.get(selector, {})

    if not selector_params or len(selector_params) == 0 or len(definition) == 0:
        return True, {}

    mkey = definition["mkey"]
    mkey_type = definition["mkey_type"]
    if mkey_type is None:
        return False, {"message": "params are not allowed for " + selector}
    mkey_value = selector_params.get(mkey)

    if not mkey_value:
        return False, {"message": "param '" + mkey + "' is required"}
    if not isinstance(mkey_value, mkey_type):
        return False, {
            "message": "param '"
            + mkey
            + "' does not match, "
            + str(mkey_type)
            + " required"
        }

    return True, {}


PLAYBOOK_BASIC_CONFIG = [
    {
        "hosts": "fortiswitch01",
        "collections": ["fortinet.fortiswitch"],
        "connection": "httpapi",
        "gather_facts": "no",
        "vars": {
            "ansible_httpapi_use_ssl": "yes",
            "ansible_httpapi_validate_certs": "no",
            "ansible_httpapi_port": 443,
        },
    }
]

EXCLUDED_LIST = ["q_origin_key"]

import copy
import traceback

YAML_IMPORT_ERROR = None
try:
    import yaml
except ImportError:
    HAS_YAML = False
    YAML_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_YAML = True


def preprocess_to_valid_data(data):
    if isinstance(data, list):
        return [preprocess_to_valid_data(elem) for elem in data]
    elif isinstance(data, dict):
        return {
            k.replace("-", "_"): preprocess_to_valid_data(v)
            for k, v in data.items()
            if k not in EXCLUDED_LIST
        }
    return data


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or not data[path[index]]
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = data[path[index]].split(" ")
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data, selector):
    multilist_attrs = SPECIAL_ATTRIBUTE_TABLE.get(selector, [])

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def fortiswitch_configuration_fact(params, fos):
    isValid, result = validate_mkey(params)
    if not isValid:
        return True, False, result

    selector = params["selector"]
    selector_params = params["params"]
    mkey_name = MODULE_MKEY_DEFINITONS[selector]["mkey"]
    mkey_value = selector_params.get(mkey_name) if selector_params else None

    [path, name] = selector.split("_")
    # XXX: The plugin level do not accept duplicated url keys, so we make only keep one key here.
    url_params = dict()
    if params["filters"] and len(params["filters"]):
        filter_body = params["filters"][0]
        for filter_item in params["filters"][1:]:
            filter_body = "%s&filter=%s" % (filter_body, filter_item)
        url_params["filter"] = filter_body

    if params["sorters"] and len(params["sorters"]):
        sorter_body = params["sorters"][0]
        for sorter_item in params["sorters"][1:]:
            sorter_body = "%s&sort=%s" % (sorter_body, sorter_item)
        url_params["sort"] = sorter_body

    if params["formatters"] and len(params["formatters"]):
        formatter_body = params["formatters"][0]
        for formatter_item in params["formatters"][1:]:
            formatter_body = "%s|%s" % (formatter_body, formatter_item)
        url_params["format"] = formatter_body

    fact = None
    if mkey_value:
        fact = fos.get(path, name, mkey=mkey_value, parameters=url_params)
    else:
        fact = fos.get(path, name, parameters=url_params)

    target_playbook = []
    selector = selector.replace(".", "_").replace("-", "_")

    # some raw results are not list so we need to wrap it first in order to use the flatten call below
    results = (
        fact.get("results")
        if isinstance(fact.get("results"), list)
        else [fact.get("results")]
    )

    for element in PLAYBOOK_BASIC_CONFIG:
        copied_element = copy.deepcopy(element)
        copied_element.update(
            {
                "tasks": [
                    {
                        "fortiswitch_"
                        + selector: {
                            "state": "present",
                            selector: {
                                k: v
                                for k, v in flatten_multilists_attributes(
                                    preprocess_to_valid_data(result), selector
                                ).items()
                                if k not in EXCLUDED_LIST
                            },
                        }
                    }
                    for result in results
                ]
            }
        )

        target_playbook.append(copied_element)

    with open(params["output_path"] + "/" + selector + "_playbook.yml", "w") as f:
        yaml.dump(target_playbook, f, sort_keys=False)

    return not is_successful_status(fact), False, fact


def main():
    fields = {
        "output_path": {"required": True, "type": "str"},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "filters": {"required": False, "type": "list", "elements": "str"},
        "sorters": {"required": False, "type": "list", "elements": "str"},
        "formatters": {"required": False, "type": "list", "elements": "str"},
        "params": {"required": False, "type": "dict"},
        "selector": {
            "required": False,
            "type": "str",
            "choices": [
                "system_vdom",
                "system_global",
                "system.alias_command",
                "system.alias_group",
                "system_accprofile",
                "system_object-tag",
                "system_interface",
                "system_password-policy",
                "system_admin",
                "system_settings",
                "system_resource-limits",
                "system_vdom-property",
                "system_dns-database",
                "system_dns-server",
                "system_arp-table",
                "system_ipv6-neighbor-cache",
                "system_location",
                "system_dns",
                "system_sflow",
                "system_vdom-dns",
                "system.snmp_sysinfo",
                "system.snmp_community",
                "system.snmp_user",
                "system.autoupdate_override",
                "system.autoupdate_push-update",
                "system.autoupdate_schedule",
                "system.autoupdate_tunneling",
                "system.autoupdate_clientoverride",
                "system_session-ttl",
                "system.dhcp_server",
                "system_port-pair",
                "system_management-tunnel",
                "system_fortimanager",
                "system_fm",
                "system_central-management",
                "system_zone",
                "system.certificate_ca",
                "system.certificate_local",
                "system.certificate_crl",
                "system.certificate_remote",
                "system.certificate_ocsp",
                "system_fortianalyzer",
                "system_fortianalyzer2",
                "system_fortianalyzer3",
                "system_fortiguard",
                "system_fortiguard-log",
                "system_alertemail",
                "system_alarm",
                "system_mac-address-table",
                "system_proxy-arp",
                "system_tos-based-priority",
                "system_link-monitor",
                "system_console",
                "system_bug-report",
                "system_ntp",
                "system_fsw-cloud",
                "system_sniffer-profile",
                "system.schedule_onetime",
                "system.schedule_recurring",
                "system.schedule_group",
                "system_flow-export",
                "router_access-list6",
                "router_prefix-list6",
                "router_vrf",
                "router_aspath-list",
                "router_community-list",
                "router_access-list",
                "router_prefix-list",
                "router_route-map",
                "router_key-chain",
                "router_static",
                "router_policy",
                "router_rip",
                "router_ripng",
                "router_isis",
                "router_multicast-flow",
                "router_multicast",
                "router_static6",
                "router_ospf",
                "router_ospf6",
                "router_bgp",
                "router_auth-path",
                "router_setting",
                "router_gwdetect",
                "switch_domain",
                "switch_global",
                "switch.lldp_settings",
                "switch.lldp_profile",
                "switch.macsec_profile",
                "switch_vlan-tpid",
                "switch.qos_dot1p-map",
                "switch.qos_ip-dscp-map",
                "switch.qos_qos-policy",
                "switch.ptp_settings",
                "switch.ptp_policy",
                "switch_physical-port",
                "switch_vlan",
                "switch_trunk",
                "switch_raguard-policy",
                "switch_interface",
                "switch.stp_settings",
                "switch.stp_instance",
                "switch_static-mac",
                "switch_mirror",
                "switch_storm-control",
                "switch.acl_policer",
                "switch.acl_settings",
                "switch.acl.service_custom",
                "switch.acl_ingress",
                "switch.acl_egress",
                "switch.acl_prelookup",
                "switch_ip-mac-binding",
                "switch.igmp-snooping_globals",
                "switch.mld-snooping_globals",
                "switch_virtual-wire",
                "switch_security-feature",
                "switch_phy-mode",
                "switch_auto-isl-port-group",
                "switch_auto-network",
                "switch.network-monitor_settings",
                "switch.network-monitor_directed",
                "switch_quarantine",
                "user_radius",
                "user_tacacs+",
                "user_ldap",
                "user_local",
                "user_setting",
                "user_peer",
                "user_peergrp",
                "user_group",
                "log_custom-field",
                "log.syslogd_setting",
                "log.syslogd_override-setting",
                "log.syslogd_filter",
                "log.syslogd_override-filter",
                "log.syslogd2_setting",
                "log.syslogd2_filter",
                "log.syslogd3_setting",
                "log.syslogd3_filter",
                "log.memory_global-setting",
                "log.memory_setting",
                "log.memory_filter",
                "log.disk_setting",
                "log.disk_filter",
                "log_eventfilter",
                "log.fortiguard_setting",
                "log.remote_setting",
                "log_gui",
                "log.fortianalyzer_setting",
                "log.fortianalyzer_override-setting",
                "log.fortianalyzer_filter",
                "log.fortianalyzer_override-filter",
                "log.fortianalyzer2_setting",
                "log.fortianalyzer2_filter",
                "log.fortianalyzer3_setting",
                "log.fortianalyzer3_filter",
                "switch-controller_global",
                "alertemail_setting",
                "gui_console",
                "switch.acl_802-1X",
                "system_flan-cloud",
                "system_email-server",
                "system_vxlan",
                "system_web",
                "system_automation-trigger",
                "system_automation-action",
                "system_automation-destination",
                "system_automation-stitch",
                "system_auto-script",
                "system.ptp_profile",
                "system.ptp_interface-policy",
                "system_debug",
                "switch_vlan-pruning",
            ],
        },
        "selectors": {
            "required": False,
            "type": "list",
            "elements": "dict",
            "options": {
                "filters": {"required": False, "type": "list", "elements": "str"},
                "sorters": {"required": False, "type": "list", "elements": "str"},
                "formatters": {"required": False, "type": "list", "elements": "str"},
                "params": {"required": False, "type": "dict"},
                "selector": {
                    "required": True,
                    "type": "str",
                    "choices": [
                        "system_vdom",
                        "system_global",
                        "system.alias_command",
                        "system.alias_group",
                        "system_accprofile",
                        "system_object-tag",
                        "system_interface",
                        "system_password-policy",
                        "system_admin",
                        "system_settings",
                        "system_resource-limits",
                        "system_vdom-property",
                        "system_dns-database",
                        "system_dns-server",
                        "system_arp-table",
                        "system_ipv6-neighbor-cache",
                        "system_location",
                        "system_dns",
                        "system_sflow",
                        "system_vdom-dns",
                        "system.snmp_sysinfo",
                        "system.snmp_community",
                        "system.snmp_user",
                        "system.autoupdate_override",
                        "system.autoupdate_push-update",
                        "system.autoupdate_schedule",
                        "system.autoupdate_tunneling",
                        "system.autoupdate_clientoverride",
                        "system_session-ttl",
                        "system.dhcp_server",
                        "system_port-pair",
                        "system_management-tunnel",
                        "system_fortimanager",
                        "system_fm",
                        "system_central-management",
                        "system_zone",
                        "system.certificate_ca",
                        "system.certificate_local",
                        "system.certificate_crl",
                        "system.certificate_remote",
                        "system.certificate_ocsp",
                        "system_fortianalyzer",
                        "system_fortianalyzer2",
                        "system_fortianalyzer3",
                        "system_fortiguard",
                        "system_fortiguard-log",
                        "system_alertemail",
                        "system_alarm",
                        "system_mac-address-table",
                        "system_proxy-arp",
                        "system_tos-based-priority",
                        "system_link-monitor",
                        "system_console",
                        "system_bug-report",
                        "system_ntp",
                        "system_fsw-cloud",
                        "system_sniffer-profile",
                        "system.schedule_onetime",
                        "system.schedule_recurring",
                        "system.schedule_group",
                        "system_flow-export",
                        "router_access-list6",
                        "router_prefix-list6",
                        "router_vrf",
                        "router_aspath-list",
                        "router_community-list",
                        "router_access-list",
                        "router_prefix-list",
                        "router_route-map",
                        "router_key-chain",
                        "router_static",
                        "router_policy",
                        "router_rip",
                        "router_ripng",
                        "router_isis",
                        "router_multicast-flow",
                        "router_multicast",
                        "router_static6",
                        "router_ospf",
                        "router_ospf6",
                        "router_bgp",
                        "router_auth-path",
                        "router_setting",
                        "router_gwdetect",
                        "switch_domain",
                        "switch_global",
                        "switch.lldp_settings",
                        "switch.lldp_profile",
                        "switch.macsec_profile",
                        "switch_vlan-tpid",
                        "switch.qos_dot1p-map",
                        "switch.qos_ip-dscp-map",
                        "switch.qos_qos-policy",
                        "switch.ptp_settings",
                        "switch.ptp_policy",
                        "switch_physical-port",
                        "switch_vlan",
                        "switch_trunk",
                        "switch_raguard-policy",
                        "switch_interface",
                        "switch.stp_settings",
                        "switch.stp_instance",
                        "switch_static-mac",
                        "switch_mirror",
                        "switch_storm-control",
                        "switch.acl_policer",
                        "switch.acl_settings",
                        "switch.acl.service_custom",
                        "switch.acl_ingress",
                        "switch.acl_egress",
                        "switch.acl_prelookup",
                        "switch_ip-mac-binding",
                        "switch.igmp-snooping_globals",
                        "switch.mld-snooping_globals",
                        "switch_virtual-wire",
                        "switch_security-feature",
                        "switch_phy-mode",
                        "switch_auto-isl-port-group",
                        "switch_auto-network",
                        "switch.network-monitor_settings",
                        "switch.network-monitor_directed",
                        "switch_quarantine",
                        "user_radius",
                        "user_tacacs+",
                        "user_ldap",
                        "user_local",
                        "user_setting",
                        "user_peer",
                        "user_peergrp",
                        "user_group",
                        "log_custom-field",
                        "log.syslogd_setting",
                        "log.syslogd_override-setting",
                        "log.syslogd_filter",
                        "log.syslogd_override-filter",
                        "log.syslogd2_setting",
                        "log.syslogd2_filter",
                        "log.syslogd3_setting",
                        "log.syslogd3_filter",
                        "log.memory_global-setting",
                        "log.memory_setting",
                        "log.memory_filter",
                        "log.disk_setting",
                        "log.disk_filter",
                        "log_eventfilter",
                        "log.fortiguard_setting",
                        "log.remote_setting",
                        "log_gui",
                        "log.fortianalyzer_setting",
                        "log.fortianalyzer_override-setting",
                        "log.fortianalyzer_filter",
                        "log.fortianalyzer_override-filter",
                        "log.fortianalyzer2_setting",
                        "log.fortianalyzer2_filter",
                        "log.fortianalyzer3_setting",
                        "log.fortianalyzer3_filter",
                        "switch-controller_global",
                        "alertemail_setting",
                        "gui_console",
                        "switch.acl_802-1X",
                        "system_flan-cloud",
                        "system_email-server",
                        "system_vxlan",
                        "system_web",
                        "system_automation-trigger",
                        "system_automation-action",
                        "system_automation-destination",
                        "system_automation-stitch",
                        "system_auto-script",
                        "system.ptp_profile",
                        "system.ptp_interface-policy",
                        "system_debug",
                        "switch_vlan-pruning",
                    ],
                },
            },
        },
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)

    # Only selector or selectors is provided.
    if (
        module.params["selector"]
        and module.params["selectors"]
        or not module.params["selector"]
        and not module.params["selectors"]
    ):
        module.fail_json(msg="please use selector or selectors in a task.")

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable", False)

        fos = FortiOSHandler(connection, module)

        if module.params["selector"]:
            is_error, has_changed, result = fortiswitch_configuration_fact(
                module.params, fos
            )
        else:
            params = module.params
            selectors = params["selectors"]
            is_error = False
            has_changed = False
            result = []
            for selector_obj in selectors:
                per_selector = {
                    "output_path": params.get("output_path"),
                }
                per_selector.update(selector_obj)
                is_error_local, has_changed_local, result_local = (
                    fortiswitch_configuration_fact(per_selector, fos)
                )

                is_error = is_error or is_error_local
                has_changed = has_changed or has_changed_local
                result.append(result_local)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and galaxy, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            if not HAS_YAML:
                module.fail_json(
                    msg="Error in repo", meta=result, exception=YAML_IMPORT_ERROR
                )


if __name__ == "__main__":
    main()
