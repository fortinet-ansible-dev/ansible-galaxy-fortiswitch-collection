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
module: fortiswitch_configuration_fact
version_added: "1.0.0"
short_description: Retrieve Facts of FortiSwitch Configurable Objects.
description:
    - Collects facts from network devices running the fortiSwitch operating system.
      This module places the facts gathered in the fact tree keyed by the respective resource name.
      This facts module will only collect those facts which user specified in playbook.
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
            - a list of selector for retrieving the fortiswitch facts
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
                    - selector for retrieving the fortigate facts
                type: str
                required: true
                choices:
                 - log.syslogd3_filter
                 - user_radius
                 - system_interface
                 - log.fortianalyzer_override-setting
                 - log_gui
                 - system_session-ttl
                 - log.memory_filter
                 - system_accprofile
                 - router_key-chain
                 - log.syslogd_filter
                 - router_aspath-list
                 - system.certificate_remote
                 - switch_domain
                 - log.fortianalyzer_filter
                 - system_arp-table
                 - switch_physical-port
                 - switch_ip-mac-binding
                 - log.disk_filter
                 - system_ntp
                 - user_tacacs+
                 - system_fm
                 - switch_static-mac
                 - system_global
                 - switch_global
                 - system_location
                 - log.syslogd2_filter
                 - system_flan-cloud
                 - system_object-tag
                 - log.syslogd_setting
                 - system_resource-limits
                 - system.autoupdate_schedule
                 - switch.acl.service_custom
                 - switch.igmp-snooping_globals
                 - switch.lldp_settings
                 - switch.network-monitor_directed
                 - user_setting
                 - log.fortianalyzer_override-filter
                 - log.fortianalyzer3_setting
                 - router_ospf6
                 - user_peergrp
                 - log.fortiguard_setting
                 - router_rip
                 - system.snmp_community
                 - switch.qos_qos-policy
                 - log.syslogd_override-filter
                 - system.snmp_user
                 - system_settings
                 - switch_mirror
                 - switch.acl_settings
                 - system_proxy-arp
                 - system_link-monitor
                 - router_prefix-list
                 - system.alias_command
                 - system_dns-server
                 - router_bgp
                 - system.autoupdate_clientoverride
                 - switch_quarantine
                 - system_fortiguard
                 - switch-controller_global
                 - system.schedule_recurring
                 - switch.ptp_policy
                 - system.schedule_group
                 - system_bug-report
                 - switch_vlan
                 - router_prefix-list6
                 - log.memory_setting
                 - system_vdom-property
                 - switch_security-feature
                 - router_auth-path
                 - system.autoupdate_tunneling
                 - user_ldap
                 - switch_auto-network
                 - log_eventfilter
                 - system.dhcp_server
                 - switch_auto-isl-port-group
                 - switch.network-monitor_settings
                 - switch.acl_policer
                 - router_access-list
                 - log.fortianalyzer3_filter
                 - switch.ptp_settings
                 - system_dns
                 - log.syslogd2_setting
                 - log.syslogd3_setting
                 - system.autoupdate_push-update
                 - system_fortianalyzer
                 - system_management-tunnel
                 - system.alias_group
                 - switch_trunk
                 - switch_vlan-tpid
                 - log.remote_setting
                 - system_sniffer-profile
                 - router_setting
                 - user_local
                 - system_fortianalyzer3
                 - system_console
                 - system.snmp_sysinfo
                 - system_password-policy
                 - router_static6
                 - router_multicast
                 - system_fortiguard-log
                 - system_fortimanager
                 - system_mac-address-table
                 - router_gwdetect
                 - log.memory_global-setting
                 - router_isis
                 - log.syslogd_override-setting
                 - router_multicast-flow
                 - router_vrf
                 - system.certificate_ocsp
                 - log.fortianalyzer2_setting
                 - router_static
                 - alertemail_setting
                 - log.fortianalyzer2_filter
                 - system_fortianalyzer2
                 - gui_console
                 - router_community-list
                 - log.fortianalyzer_setting
                 - switch.acl_egress
                 - switch.lldp_profile
                 - system.autoupdate_override
                 - user_peer
                 - system_central-management
                 - switch.qos_dot1p-map
                 - switch_virtual-wire
                 - system.certificate_crl
                 - switch.acl_ingress
                 - system_flow-export
                 - system.certificate_local
                 - system_alertemail
                 - router_ripng
                 - switch_raguard-policy
                 - router_policy
                 - system_fsw-cloud
                 - system_zone
                 - system_vdom-dns
                 - system_tos-based-priority
                 - router_route-map
                 - system.schedule_onetime
                 - router_ospf
                 - log_custom-field
                 - system_dns-database
                 - switch_storm-control
                 - system_admin
                 - system_port-pair
                 - switch.stp_instance
                 - system_sflow
                 - router_access-list6
                 - system_vdom
                 - switch.acl_prelookup
                 - system_alarm
                 - system_ipv6-neighbor-cache
                 - user_group
                 - switch.macsec_profile
                 - switch_interface
                 - switch.qos_ip-dscp-map
                 - switch.stp_settings
                 - switch.acl_802-1X
                 - system.certificate_ca
                 - switch.mld-snooping_globals
                 - log.disk_setting
                 - switch_phy-mode

    selector:
        description:
            - selector for retrieving the fortigate facts
        type: str
        required: false
        choices:
         - log.syslogd3_filter
         - user_radius
         - system_interface
         - log.fortianalyzer_override-setting
         - log_gui
         - system_session-ttl
         - log.memory_filter
         - system_accprofile
         - router_key-chain
         - log.syslogd_filter
         - router_aspath-list
         - system.certificate_remote
         - switch_domain
         - log.fortianalyzer_filter
         - system_arp-table
         - switch_physical-port
         - switch_ip-mac-binding
         - log.disk_filter
         - system_ntp
         - user_tacacs+
         - system_fm
         - switch_static-mac
         - system_global
         - switch_global
         - system_location
         - log.syslogd2_filter
         - system_flan-cloud
         - system_object-tag
         - log.syslogd_setting
         - system_resource-limits
         - system.autoupdate_schedule
         - switch.acl.service_custom
         - switch.igmp-snooping_globals
         - switch.lldp_settings
         - switch.network-monitor_directed
         - user_setting
         - log.fortianalyzer_override-filter
         - log.fortianalyzer3_setting
         - router_ospf6
         - user_peergrp
         - log.fortiguard_setting
         - router_rip
         - system.snmp_community
         - switch.qos_qos-policy
         - log.syslogd_override-filter
         - system.snmp_user
         - system_settings
         - switch_mirror
         - switch.acl_settings
         - system_proxy-arp
         - system_link-monitor
         - router_prefix-list
         - system.alias_command
         - system_dns-server
         - router_bgp
         - system.autoupdate_clientoverride
         - switch_quarantine
         - system_fortiguard
         - switch-controller_global
         - system.schedule_recurring
         - switch.ptp_policy
         - system.schedule_group
         - system_bug-report
         - switch_vlan
         - router_prefix-list6
         - log.memory_setting
         - system_vdom-property
         - switch_security-feature
         - router_auth-path
         - system.autoupdate_tunneling
         - user_ldap
         - switch_auto-network
         - log_eventfilter
         - system.dhcp_server
         - switch_auto-isl-port-group
         - switch.network-monitor_settings
         - switch.acl_policer
         - router_access-list
         - log.fortianalyzer3_filter
         - switch.ptp_settings
         - system_dns
         - log.syslogd2_setting
         - log.syslogd3_setting
         - system.autoupdate_push-update
         - system_fortianalyzer
         - system_management-tunnel
         - system.alias_group
         - switch_trunk
         - switch_vlan-tpid
         - log.remote_setting
         - system_sniffer-profile
         - router_setting
         - user_local
         - system_fortianalyzer3
         - system_console
         - system.snmp_sysinfo
         - system_password-policy
         - router_static6
         - router_multicast
         - system_fortiguard-log
         - system_fortimanager
         - system_mac-address-table
         - router_gwdetect
         - log.memory_global-setting
         - router_isis
         - log.syslogd_override-setting
         - router_multicast-flow
         - router_vrf
         - system.certificate_ocsp
         - log.fortianalyzer2_setting
         - router_static
         - alertemail_setting
         - log.fortianalyzer2_filter
         - system_fortianalyzer2
         - gui_console
         - router_community-list
         - log.fortianalyzer_setting
         - switch.acl_egress
         - switch.lldp_profile
         - system.autoupdate_override
         - user_peer
         - system_central-management
         - switch.qos_dot1p-map
         - switch_virtual-wire
         - system.certificate_crl
         - switch.acl_ingress
         - system_flow-export
         - system.certificate_local
         - system_alertemail
         - router_ripng
         - switch_raguard-policy
         - router_policy
         - system_fsw-cloud
         - system_zone
         - system_vdom-dns
         - system_tos-based-priority
         - router_route-map
         - system.schedule_onetime
         - router_ospf
         - log_custom-field
         - system_dns-database
         - switch_storm-control
         - system_admin
         - system_port-pair
         - switch.stp_instance
         - system_sflow
         - router_access-list6
         - system_vdom
         - switch.acl_prelookup
         - system_alarm
         - system_ipv6-neighbor-cache
         - user_group
         - switch.macsec_profile
         - switch_interface
         - switch.qos_ip-dscp-map
         - switch.stp_settings
         - switch.acl_802-1X
         - system.certificate_ca
         - switch.mld-snooping_globals
         - log.disk_setting
         - switch_phy-mode

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
  - name: Get multiple selectors info concurrently
    fortiswitch_configuration_fact:
      selectors:
        - selector: system_interface
          params:
            name: "port1"

  - name: fact gathering
    fortiswitch_configuration_fact:
        filters:
            - name==port1
            - vlanid==0
        sorters:
            - name,vlanid
            - management-ip
        formatters:
         - name
         - management-ip
         - vlanid
        selector: 'system_interface'

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
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v7.0.0"
ansible_facts:
  description: The list of fact subsets collected from the device
  returned: always
  type: dict

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.fortiswitch_handler import FortiOSHandler
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG

MODULE_MKEY_DEFINITONS = {
    "log.syslogd3_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_radius": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_interface": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortianalyzer_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log_gui": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_session-ttl": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.memory_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_accprofile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_key-chain": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_aspath-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.certificate_remote": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch_domain": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortianalyzer_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_arp-table": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch_physical-port": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch_ip-mac-binding": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "log.disk_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ntp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_tacacs+": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_fm": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch_static-mac": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "system_global": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch_global": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_location": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd2_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_flan-cloud": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_object-tag": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_resource-limits": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.autoupdate_schedule": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch.acl.service_custom": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.igmp-snooping_globals": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch.lldp_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch.network-monitor_directed": {
        "mkey_type": int,
        "mkey": "id",
    },
    "user_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer3_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_ospf6": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_peergrp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortiguard_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_rip": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.snmp_community": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch.qos_qos-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.snmp_user": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch_mirror": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.acl_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_proxy-arp": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_link-monitor": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_prefix-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.alias_command": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_dns-server": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_bgp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.autoupdate_clientoverride": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch_quarantine": {
        "mkey_type": str,
        "mkey": "mac",
    },
    "system_fortiguard": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_global": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.schedule_recurring": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.ptp_policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.schedule_group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_bug-report": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch_vlan": {
        "mkey_type": int,
        "mkey": "id",
    },
    "router_prefix-list6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.memory_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_vdom-property": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch_security-feature": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_auth-path": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.autoupdate_tunneling": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_ldap": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch_auto-network": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log_eventfilter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.dhcp_server": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch_auto-isl-port-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.network-monitor_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch.acl_policer": {
        "mkey_type": int,
        "mkey": "id",
    },
    "router_access-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortianalyzer3_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch.ptp_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_dns": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd2_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd3_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.autoupdate_push-update": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_fortianalyzer": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_management-tunnel": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.alias_group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch_trunk": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch_vlan-tpid": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.remote_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_sniffer-profile": {
        "mkey_type": str,
        "mkey": "profile_name",
    },
    "router_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_local": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_fortianalyzer3": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_console": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.snmp_sysinfo": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_password-policy": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_static6": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "router_multicast": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_fortiguard-log": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_fortimanager": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_mac-address-table": {
        "mkey_type": str,
        "mkey": "mac",
    },
    "router_gwdetect": {
        "mkey_type": str,
        "mkey": "interface",
    },
    "log.memory_global-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_isis": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_multicast-flow": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_vrf": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.certificate_ocsp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer2_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_static": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "alertemail_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer2_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_fortianalyzer2": {
        "mkey_type": None,
        "mkey": "None",
    },
    "gui_console": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_community-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortianalyzer_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch.acl_egress": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch.lldp_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.autoupdate_override": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_peer": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_central-management": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch.qos_dot1p-map": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch_virtual-wire": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.certificate_crl": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.acl_ingress": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_flow-export": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.certificate_local": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_alertemail": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_ripng": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch_raguard-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_policy": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "system_fsw-cloud": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_zone": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_vdom-dns": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_tos-based-priority": {
        "mkey_type": int,
        "mkey": "id",
    },
    "router_route-map": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.schedule_onetime": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_ospf": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log_custom-field": {
        "mkey_type": str,
        "mkey": "id",
    },
    "system_dns-database": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch_storm-control": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_admin": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_port-pair": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.stp_instance": {
        "mkey_type": str,
        "mkey": "id",
    },
    "system_sflow": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_access-list6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_vdom": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.acl_prelookup": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_alarm": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ipv6-neighbor-cache": {
        "mkey_type": int,
        "mkey": "id",
    },
    "user_group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.macsec_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch_interface": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.qos_ip-dscp-map": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.stp_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch.acl_802-1X": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system.certificate_ca": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch.mld-snooping_globals": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.disk_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch_phy-mode": {
        "mkey_type": None,
        "mkey": "None",
    },
}


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def validate_mkey(params):
    selector = params['selector']
    selector_params = params.get('params', {})

    if selector not in MODULE_MKEY_DEFINITONS:
        return False, {"message": "unknown selector: " + selector}

    definition = MODULE_MKEY_DEFINITONS.get(selector, {})

    if not selector_params or len(selector_params) == 0 or len(definition) == 0:
        return True, {}

    mkey = definition['mkey']
    mkey_type = definition['mkey_type']
    if mkey_type is None:
        return False, {"message": "params are not allowed for " + selector}
    mkey_value = selector_params.get(mkey)

    if not mkey_value:
        return False, {"message": "param '" + mkey + "' is required"}
    if not isinstance(mkey_value, mkey_type):
        return False, {"message": "param '" + mkey + "' does not match, " + str(mkey_type) + " required"}

    return True, {}


def fortiswitch_configuration_fact(params, fos):
    isValid, result = validate_mkey(params)
    if not isValid:
        return True, False, result

    selector = params['selector']
    selector_params = params['params']
    mkey_name = MODULE_MKEY_DEFINITONS[selector]['mkey']
    mkey_value = selector_params.get(mkey_name) if selector_params else None

    [path, name] = selector.split('_')
    # XXX: The plugin level do not accept duplicated url keys, so we make only keep one key here.
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

    fact = None
    if mkey_value:
        fact = fos.get(path, name, mkey=mkey_value, parameters=url_params)
    else:
        fact = fos.get(path, name, parameters=url_params)

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
                "log.syslogd3_filter",
                "user_radius",
                "system_interface",
                "log.fortianalyzer_override-setting",
                "log_gui",
                "system_session-ttl",
                "log.memory_filter",
                "system_accprofile",
                "router_key-chain",
                "log.syslogd_filter",
                "router_aspath-list",
                "system.certificate_remote",
                "switch_domain",
                "log.fortianalyzer_filter",
                "system_arp-table",
                "switch_physical-port",
                "switch_ip-mac-binding",
                "log.disk_filter",
                "system_ntp",
                "user_tacacs+",
                "system_fm",
                "switch_static-mac",
                "system_global",
                "switch_global",
                "system_location",
                "log.syslogd2_filter",
                "system_flan-cloud",
                "system_object-tag",
                "log.syslogd_setting",
                "system_resource-limits",
                "system.autoupdate_schedule",
                "switch.acl.service_custom",
                "switch.igmp-snooping_globals",
                "switch.lldp_settings",
                "switch.network-monitor_directed",
                "user_setting",
                "log.fortianalyzer_override-filter",
                "log.fortianalyzer3_setting",
                "router_ospf6",
                "user_peergrp",
                "log.fortiguard_setting",
                "router_rip",
                "system.snmp_community",
                "switch.qos_qos-policy",
                "log.syslogd_override-filter",
                "system.snmp_user",
                "system_settings",
                "switch_mirror",
                "switch.acl_settings",
                "system_proxy-arp",
                "system_link-monitor",
                "router_prefix-list",
                "system.alias_command",
                "system_dns-server",
                "router_bgp",
                "system.autoupdate_clientoverride",
                "switch_quarantine",
                "system_fortiguard",
                "switch-controller_global",
                "system.schedule_recurring",
                "switch.ptp_policy",
                "system.schedule_group",
                "system_bug-report",
                "switch_vlan",
                "router_prefix-list6",
                "log.memory_setting",
                "system_vdom-property",
                "switch_security-feature",
                "router_auth-path",
                "system.autoupdate_tunneling",
                "user_ldap",
                "switch_auto-network",
                "log_eventfilter",
                "system.dhcp_server",
                "switch_auto-isl-port-group",
                "switch.network-monitor_settings",
                "switch.acl_policer",
                "router_access-list",
                "log.fortianalyzer3_filter",
                "switch.ptp_settings",
                "system_dns",
                "log.syslogd2_setting",
                "log.syslogd3_setting",
                "system.autoupdate_push-update",
                "system_fortianalyzer",
                "system_management-tunnel",
                "system.alias_group",
                "switch_trunk",
                "switch_vlan-tpid",
                "log.remote_setting",
                "system_sniffer-profile",
                "router_setting",
                "user_local",
                "system_fortianalyzer3",
                "system_console",
                "system.snmp_sysinfo",
                "system_password-policy",
                "router_static6",
                "router_multicast",
                "system_fortiguard-log",
                "system_fortimanager",
                "system_mac-address-table",
                "router_gwdetect",
                "log.memory_global-setting",
                "router_isis",
                "log.syslogd_override-setting",
                "router_multicast-flow",
                "router_vrf",
                "system.certificate_ocsp",
                "log.fortianalyzer2_setting",
                "router_static",
                "alertemail_setting",
                "log.fortianalyzer2_filter",
                "system_fortianalyzer2",
                "gui_console",
                "router_community-list",
                "log.fortianalyzer_setting",
                "switch.acl_egress",
                "switch.lldp_profile",
                "system.autoupdate_override",
                "user_peer",
                "system_central-management",
                "switch.qos_dot1p-map",
                "switch_virtual-wire",
                "system.certificate_crl",
                "switch.acl_ingress",
                "system_flow-export",
                "system.certificate_local",
                "system_alertemail",
                "router_ripng",
                "switch_raguard-policy",
                "router_policy",
                "system_fsw-cloud",
                "system_zone",
                "system_vdom-dns",
                "system_tos-based-priority",
                "router_route-map",
                "system.schedule_onetime",
                "router_ospf",
                "log_custom-field",
                "system_dns-database",
                "switch_storm-control",
                "system_admin",
                "system_port-pair",
                "switch.stp_instance",
                "system_sflow",
                "router_access-list6",
                "system_vdom",
                "switch.acl_prelookup",
                "system_alarm",
                "system_ipv6-neighbor-cache",
                "user_group",
                "switch.macsec_profile",
                "switch_interface",
                "switch.qos_ip-dscp-map",
                "switch.stp_settings",
                "switch.acl_802-1X",
                "system.certificate_ca",
                "switch.mld-snooping_globals",
                "log.disk_setting",
                "switch_phy-mode",
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
                        "log.syslogd3_filter",
                        "user_radius",
                        "system_interface",
                        "log.fortianalyzer_override-setting",
                        "log_gui",
                        "system_session-ttl",
                        "log.memory_filter",
                        "system_accprofile",
                        "router_key-chain",
                        "log.syslogd_filter",
                        "router_aspath-list",
                        "system.certificate_remote",
                        "switch_domain",
                        "log.fortianalyzer_filter",
                        "system_arp-table",
                        "switch_physical-port",
                        "switch_ip-mac-binding",
                        "log.disk_filter",
                        "system_ntp",
                        "user_tacacs+",
                        "system_fm",
                        "switch_static-mac",
                        "system_global",
                        "switch_global",
                        "system_location",
                        "log.syslogd2_filter",
                        "system_flan-cloud",
                        "system_object-tag",
                        "log.syslogd_setting",
                        "system_resource-limits",
                        "system.autoupdate_schedule",
                        "switch.acl.service_custom",
                        "switch.igmp-snooping_globals",
                        "switch.lldp_settings",
                        "switch.network-monitor_directed",
                        "user_setting",
                        "log.fortianalyzer_override-filter",
                        "log.fortianalyzer3_setting",
                        "router_ospf6",
                        "user_peergrp",
                        "log.fortiguard_setting",
                        "router_rip",
                        "system.snmp_community",
                        "switch.qos_qos-policy",
                        "log.syslogd_override-filter",
                        "system.snmp_user",
                        "system_settings",
                        "switch_mirror",
                        "switch.acl_settings",
                        "system_proxy-arp",
                        "system_link-monitor",
                        "router_prefix-list",
                        "system.alias_command",
                        "system_dns-server",
                        "router_bgp",
                        "system.autoupdate_clientoverride",
                        "switch_quarantine",
                        "system_fortiguard",
                        "switch-controller_global",
                        "system.schedule_recurring",
                        "switch.ptp_policy",
                        "system.schedule_group",
                        "system_bug-report",
                        "switch_vlan",
                        "router_prefix-list6",
                        "log.memory_setting",
                        "system_vdom-property",
                        "switch_security-feature",
                        "router_auth-path",
                        "system.autoupdate_tunneling",
                        "user_ldap",
                        "switch_auto-network",
                        "log_eventfilter",
                        "system.dhcp_server",
                        "switch_auto-isl-port-group",
                        "switch.network-monitor_settings",
                        "switch.acl_policer",
                        "router_access-list",
                        "log.fortianalyzer3_filter",
                        "switch.ptp_settings",
                        "system_dns",
                        "log.syslogd2_setting",
                        "log.syslogd3_setting",
                        "system.autoupdate_push-update",
                        "system_fortianalyzer",
                        "system_management-tunnel",
                        "system.alias_group",
                        "switch_trunk",
                        "switch_vlan-tpid",
                        "log.remote_setting",
                        "system_sniffer-profile",
                        "router_setting",
                        "user_local",
                        "system_fortianalyzer3",
                        "system_console",
                        "system.snmp_sysinfo",
                        "system_password-policy",
                        "router_static6",
                        "router_multicast",
                        "system_fortiguard-log",
                        "system_fortimanager",
                        "system_mac-address-table",
                        "router_gwdetect",
                        "log.memory_global-setting",
                        "router_isis",
                        "log.syslogd_override-setting",
                        "router_multicast-flow",
                        "router_vrf",
                        "system.certificate_ocsp",
                        "log.fortianalyzer2_setting",
                        "router_static",
                        "alertemail_setting",
                        "log.fortianalyzer2_filter",
                        "system_fortianalyzer2",
                        "gui_console",
                        "router_community-list",
                        "log.fortianalyzer_setting",
                        "switch.acl_egress",
                        "switch.lldp_profile",
                        "system.autoupdate_override",
                        "user_peer",
                        "system_central-management",
                        "switch.qos_dot1p-map",
                        "switch_virtual-wire",
                        "system.certificate_crl",
                        "switch.acl_ingress",
                        "system_flow-export",
                        "system.certificate_local",
                        "system_alertemail",
                        "router_ripng",
                        "switch_raguard-policy",
                        "router_policy",
                        "system_fsw-cloud",
                        "system_zone",
                        "system_vdom-dns",
                        "system_tos-based-priority",
                        "router_route-map",
                        "system.schedule_onetime",
                        "router_ospf",
                        "log_custom-field",
                        "system_dns-database",
                        "switch_storm-control",
                        "system_admin",
                        "system_port-pair",
                        "switch.stp_instance",
                        "system_sflow",
                        "router_access-list6",
                        "system_vdom",
                        "switch.acl_prelookup",
                        "system_alarm",
                        "system_ipv6-neighbor-cache",
                        "user_group",
                        "switch.macsec_profile",
                        "switch_interface",
                        "switch.qos_ip-dscp-map",
                        "switch.stp_settings",
                        "switch.acl_802-1X",
                        "system.certificate_ca",
                        "switch.mld-snooping_globals",
                        "log.disk_setting",
                        "switch_phy-mode",
                    ],
                },
            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    # Only selector or selectors is provided.
    if module.params['selector'] and module.params['selectors'] or \
            not module.params['selector'] and not module.params['selectors']:
        module.fail_json(msg="please use selector or selectors in a task.")

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)

        fos = FortiOSHandler(connection, module)

        if module.params['selector']:
            is_error, has_changed, result = fortiswitch_configuration_fact(module.params, fos)
        else:
            params = module.params
            selectors = params['selectors']
            is_error = False
            has_changed = False
            result = []
            for selector_obj in selectors:
                is_error_local, has_changed_local, result_local = fortiswitch_configuration_fact(selector_obj, fos)

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
