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
module: fortiswitch_system_interface
short_description: Configure interfaces in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and interface category.
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
    - ansible>=2.14
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
    system_interface:
        description:
            - Configure interfaces.
        default: null
        type: dict
        suboptions:
            alias:
                description:
                    - Alias.
                type: str
            allowaccess:
                description:
                    - Interface management access.
                type: list
                elements: str
                choices:
                    - 'ping'
                    - 'https'
                    - 'http'
                    - 'ssh'
                    - 'snmp'
                    - 'telnet'
                    - 'radius-acct'
            auth_type:
                description:
                    - PPP authentication type.
                type: str
                choices:
                    - 'auto'
                    - 'pap'
                    - 'chap'
                    - 'mschapv1'
                    - 'mschapv2'
            bfd:
                description:
                    - Bidirectional Forwarding Detection (BFD).
                type: str
                choices:
                    - 'global'
                    - 'enable'
                    - 'disable'
            bfd_desired_min_tx:
                description:
                    - BFD desired minimal transmit interval.
                type: int
            bfd_detect_mult:
                description:
                    - BFD detection multiplier.
                type: int
            bfd_required_min_rx:
                description:
                    - BFD required minimal receive interval.
                type: int
            cli_conn_status:
                description:
                    - CLI connection status.
                type: str
                choices:
                    - 'initial'
                    - 'connecting'
                    - 'connected'
                    - 'failed'
            defaultgw:
                description:
                    - Enable/disable default gateway.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            description:
                description:
                    - Description.
                type: str
            detectprotocol:
                description:
                    - Protocol to use for gateway detection.
                type: str
                choices:
                    - 'ping'
                    - 'tcp-echo'
                    - 'udp-echo'
            detectserver:
                description:
                    - IP address to PING for gateway detection.
                type: str
            dhcp_client_identifier:
                description:
                    - DHCP client identifier.
                type: str
            dhcp_client_status:
                description:
                    - DHCP client connection status.
                type: str
                choices:
                    - 'initial'
                    - 'stopped'
                    - 'connected'
                    - 'rebooting'
                    - 'selecting'
                    - 'requesting'
                    - 'binding'
                    - 'renewing'
                    - 'rebinding'
            dhcp_expire:
                description:
                    - DHCP client expiration.
                type: int
            dhcp_relay_ip:
                description:
                    - DHCP relay IP address.
                type: str
            dhcp_relay_option82:
                description:
                    - Enable / Disable DHCP relay option-82 insertion.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_relay_service:
                description:
                    - Enable/disable use DHCP relay service.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_vendor_specific_option:
                description:
                    - DHCP Vendor specific option 43.
                type: str
            distance:
                description:
                    - Distance of learned routes.
                type: int
            dns_server_override:
                description:
                    - Enable/disable use of DNS server aquired by DHCP or PPPoE.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dynamic_dns1:
                description:
                    - Primary dynamic DNS server.
                type: str
            dynamic_dns2:
                description:
                    - Secondary dynamic DNS server.
                type: str
            dynamicgw:
                description:
                    - Dynamic gateway.
                type: str
            forward_domain:
                description:
                    - TP mode forward domain.
                type: int
            gwdetect:
                description:
                    - Enable/disable gateway detection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ha_priority:
                description:
                    - PING server HA election priority (1 - 50).
                type: int
            icmp_redirect:
                description:
                    - Enable/disable ICMP rediect.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            interface:
                description:
                    - Interface name.
                type: str
            ip:
                description:
                    - Interface IPv4 address.
                type: str
            ipv6:
                description:
                    - IPv6 address.
                type: dict
                suboptions:
                    autoconf:
                        description:
                            - Enable/disable address automatic config.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    dhcp6_information_request:
                        description:
                            - Enable/disable DHCPv6 information request.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ip6_address:
                        description:
                            - Primary IPv6 address prefix of interface.
                        type: str
                    ip6_allowaccess:
                        description:
                            - Allow management access to the interface.
                        type: str
                        choices:
                            - 'any'
                            - 'ping'
                            - 'https'
                            - 'http'
                            - 'ssh'
                            - 'snmp'
                            - 'telnet'
                            - 'radius-acct'
                    ip6_default_life:
                        description:
                            - IPv6 default life (sec).
                        type: int
                    ip6_dns_server_override:
                        description:
                            - Enable/disable using the DNS server acquired by DHCP.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ip6_extra_addr:
                        description:
                            - Extra IPv6 address prefixes of interface.
                        type: list
                        elements: dict
                        suboptions:
                            prefix:
                                description:
                                    - IPv6 address prefix.
                                type: str
                    ip6_hop_limit:
                        description:
                            - IPv6 hop limit.
                        type: int
                    ip6_link_mtu:
                        description:
                            - IPv6 link MTU.
                        type: int
                    ip6_manage_flag:
                        description:
                            - Enable/disable sending of IPv6 managed flag.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ip6_max_interval:
                        description:
                            - IPv6 maximum interval (sec) after which RA will be sent.
                        type: int
                    ip6_min_interval:
                        description:
                            - IPv6 minimum interval (sec) after which RA will be sent.
                        type: int
                    ip6_mode:
                        description:
                            - Addressing mode (static, DHCP).
                        type: str
                        choices:
                            - 'static'
                            - 'dhcp'
                    ip6_other_flag:
                        description:
                            - Enable/disable sending of IPv6 other flag.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ip6_prefix_list:
                        description:
                            - IPv6 advertised prefix list.
                        type: list
                        elements: dict
                        suboptions:
                            autonomous_flag:
                                description:
                                    - Enable/disable autonomous flag.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            onlink_flag:
                                description:
                                    - Enable/disable onlink flag.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            preferred_life_time:
                                description:
                                    - Preferred life time (sec).
                                type: int
                            prefix:
                                description:
                                    - IPv6 prefix.
                                type: str
                            valid_life_time:
                                description:
                                    - Valid life time (sec).
                                type: int
                    ip6_reachable_time:
                        description:
                            - IPv6 reachable time (milliseconds).
                        type: int
                    ip6_retrans_time:
                        description:
                            - IPv6 retransmit time (milliseconds).
                        type: int
                    ip6_send_adv:
                        description:
                            - Enable/disable sending of IPv6 Router advertisement.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ip6_unknown_mcast_to_cpu:
                        description:
                            - Enable/disable unknown mcast to cpu.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    vrip6_link_local:
                        description:
                            - Link-local IPv6 address of virtual router.
                        type: str
                    vrrp6:
                        description:
                            - IPv6 VRRP configuration.
                        type: list
                        elements: dict
                        suboptions:
                            accept_mode:
                                description:
                                    - Enable/disable accept mode.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            adv_interval:
                                description:
                                    - Advertisement interval (1 - 255 seconds).
                                type: int
                            preempt:
                                description:
                                    - Enable/disable preempt mode.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            priority:
                                description:
                                    - Priority of the virtual router (1 - 255).
                                type: int
                            start_time:
                                description:
                                    - Startup time (1 - 255 seconds).
                                type: int
                            status:
                                description:
                                    - Enable/disable VRRP.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            vrdst6:
                                description:
                                    - Monitor the route to this destination.
                                type: str
                            vrgrp:
                                description:
                                    - VRRP group ID (1 - 65535).
                                type: int
                            vrid:
                                description:
                                    - Virtual router identifier (1 - 255).
                                type: int
                            vrip6:
                                description:
                                    - IPv6 address of the virtual router.
                                type: str
                    vrrp_virtual_mac6:
                        description:
                            - Enable/disable virtual MAC for VRRP.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            l2_interface:
                description:
                    - L2 interface name.
                type: str
            macaddr:
                description:
                    - MAC address.
                type: str
            mode:
                description:
                    - Interface addressing mode.
                type: str
                choices:
                    - 'static'
                    - 'dhcp'
            mtu:
                description:
                    - Maximum transportation unit (MTU).
                type: int
            mtu_override:
                description:
                    - Enable/disable override of default MTU.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Name.
                required: true
                type: str
            ping_serv_status:
                description:
                    - PING server status.
                type: int
            priority:
                description:
                    - Priority of learned routes.
                type: int
            remote_ip:
                description:
                    - Remote IP address of tunnel.
                type: str
            secondary_IP:
                description:
                    - Enable/disable use of secondary IP address.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            secondaryip:
                description:
                    - Second IP address of interface.
                type: list
                elements: dict
                suboptions:
                    allowaccess:
                        description:
                            - Interface management access.
                        type: list
                        elements: str
                        choices:
                            - 'ping'
                            - 'https'
                            - 'http'
                            - 'ssh'
                            - 'snmp'
                            - 'telnet'
                            - 'radius-acct'
                    detectprotocol:
                        description:
                            - Protocol to use for gateway detection.
                        type: str
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                    detectserver:
                        description:
                            - IP address to PING for gateway detection.
                        type: str
                    gwdetect:
                        description:
                            - Enable/disable gateway detection.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ha_priority:
                        description:
                            - PING server HA election priority (1 - 50).
                        type: int
                    id:
                        description:
                            - Id.
                        type: int
                    ip:
                        description:
                            - Interface IPv4 address.
                        type: str
                    ping_serv_status:
                        description:
                            - PING server status.
                        type: int
            snmp_index:
                description:
                    - SNMP index.
                type: int
            speed:
                description:
                    - Speed (copper mode port only).
                type: str
                choices:
                    - 'auto'
                    - '10full'
                    - '10half'
                    - '100full'
                    - '100half'
                    - '1000full'
                    - '1000half'
                    - '1000auto'
            src_check:
                description:
                    - Enable/disable source IP check.
                type: str
                choices:
                    - 'disable'
                    - 'loose'
                    - 'strict'
            src_check_allow_default:
                description:
                    - Enable/disable.When src ip lookup hits default route,enable means allow pkt else drop.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            status:
                description:
                    - Interface status.
                type: str
                choices:
                    - 'up'
                    - 'down'
            switch:
                description:
                    - Contained in switch.
                type: str
            switch_members:
                description:
                    - Switch interfaces.
                type: list
                elements: dict
                suboptions:
                    member_name:
                        description:
                            - Interface name.
                        type: str
            type:
                description:
                    - Interface type.
                type: str
                choices:
                    - 'physical'
                    - 'vlan'
                    - 'tunnel'
                    - 'loopback'
                    - 'switch'
                    - 'hard-switch'
                    - 'vap-switch'
                    - 'hdlc'
                    - 'vxlan'
            vdom:
                description:
                    - Virtual domain name.
                type: str
            vlanforward:
                description:
                    - Enable/disable VLAN forwarding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vlanid:
                description:
                    - VLAN ID.
                type: int
            vrf:
                description:
                    - VRF.
                type: str
            vrrp:
                description:
                    - VRRP configuration
                type: list
                elements: dict
                suboptions:
                    adv_interval:
                        description:
                            - Advertisement interval (1 - 255 seconds).
                        type: int
                    backup_vmac_fwd:
                        description:
                            - Enable/disable backup-vmac-fwd.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    preempt:
                        description:
                            - Enable/disable preempt mode.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    priority:
                        description:
                            - Priority of the virtual router (1 - 255).
                        type: int
                    start_time:
                        description:
                            - Startup time (1 - 255 seconds).
                        type: int
                    status:
                        description:
                            - Enable/disable status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    version:
                        description:
                            - VRRP version.
                        type: str
                        choices:
                            - '2'
                            - '3'
                    vrdst:
                        description:
                            - Monitor the route to this destination.
                        type: str
                    vrgrp:
                        description:
                            - VRRP group ID (1 - 65535).
                        type: int
                    vrid:
                        description:
                            - Virtual router identifier (1 - 255).
                        type: int
                    vrip:
                        description:
                            - IP address of the virtual router.
                        type: str
            vrrp_virtual_mac:
                description:
                    - enable to use virtual MAC for VRRP
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            weight:
                description:
                    - Default weight for static routes if route has no weight configured (0 - 255).
                type: int
'''

EXAMPLES = '''
- name: Configure interfaces.
  fortinet.fortiswitch.fortiswitch_system_interface:
      state: "present"
      system_interface:
          alias: "<your_own_value>"
          allowaccess: "ping"
          auth_type: "auto"
          bfd: "global"
          bfd_desired_min_tx: "7"
          bfd_detect_mult: "8"
          bfd_required_min_rx: "9"
          cli_conn_status: "initial"
          defaultgw: "enable"
          description: "<your_own_value>"
          detectprotocol: "ping"
          detectserver: "<your_own_value>"
          dhcp_client_identifier: "myId_15"
          dhcp_client_status: "initial"
          dhcp_expire: "17"
          dhcp_relay_ip: "<your_own_value>"
          dhcp_relay_option82: "disable"
          dhcp_relay_service: "disable"
          dhcp_vendor_specific_option: "<your_own_value>"
          distance: "22"
          dns_server_override: "enable"
          dynamic_dns1: "<your_own_value>"
          dynamic_dns2: "<your_own_value>"
          dynamicgw: "<your_own_value>"
          forward_domain: "27"
          gwdetect: "enable"
          ha_priority: "29"
          icmp_redirect: "enable"
          interface: "<your_own_value> (source system.interface.name)"
          ip: "<your_own_value>"
          ipv6:
              autoconf: "enable"
              dhcp6_information_request: "enable"
              ip6_address: "<your_own_value>"
              ip6_allowaccess: "any"
              ip6_default_life: "38"
              ip6_dns_server_override: "enable"
              ip6_extra_addr:
                  -
                      prefix: "<your_own_value>"
              ip6_hop_limit: "42"
              ip6_link_mtu: "43"
              ip6_manage_flag: "enable"
              ip6_max_interval: "45"
              ip6_min_interval: "46"
              ip6_mode: "static"
              ip6_other_flag: "enable"
              ip6_prefix_list:
                  -
                      autonomous_flag: "enable"
                      onlink_flag: "enable"
                      preferred_life_time: "52"
                      prefix: "<your_own_value>"
                      valid_life_time: "54"
              ip6_reachable_time: "55"
              ip6_retrans_time: "56"
              ip6_send_adv: "enable"
              ip6_unknown_mcast_to_cpu: "enable"
              vrip6_link_local: "<your_own_value>"
              vrrp6:
                  -
                      accept_mode: "enable"
                      adv_interval: "62"
                      preempt: "enable"
                      priority: "64"
                      start_time: "65"
                      status: "enable"
                      vrdst6: "<your_own_value>"
                      vrgrp: "68"
                      vrid: "69"
                      vrip6: "<your_own_value>"
              vrrp_virtual_mac6: "enable"
          l2_interface: "<your_own_value> (source switch.interface.name)"
          macaddr: "<your_own_value>"
          mode: "static"
          mtu: "75"
          mtu_override: "enable"
          name: "default_name_77"
          ping_serv_status: "78"
          priority: "79"
          remote_ip: "<your_own_value>"
          secondary_IP: "enable"
          secondaryip:
              -
                  allowaccess: "ping"
                  detectprotocol: "ping"
                  detectserver: "<your_own_value>"
                  gwdetect: "enable"
                  ha_priority: "87"
                  id: "88"
                  ip: "<your_own_value>"
                  ping_serv_status: "90"
          snmp_index: "91"
          speed: "auto"
          src_check: "disable"
          src_check_allow_default: "enable"
          status: "up"
          switch: "<your_own_value>"
          switch_members:
              -
                  member_name: "<your_own_value> (source switch.interface.name)"
          type: "physical"
          vdom: "<your_own_value> (source system.vdom.name)"
          vlanforward: "enable"
          vlanid: "102"
          vrf: "<your_own_value> (source router.vrf.name)"
          vrrp:
              -
                  adv_interval: "105"
                  backup_vmac_fwd: "enable"
                  preempt: "enable"
                  priority: "108"
                  start_time: "109"
                  status: "enable"
                  version: "2"
                  vrdst: "<your_own_value>"
                  vrgrp: "113"
                  vrid: "114"
                  vrip: "<your_own_value>"
          vrrp_virtual_mac: "enable"
          weight: "117"
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


def filter_system_interface_data(json):
    option_list = ['alias', 'allowaccess', 'auth_type',
                   'bfd', 'bfd_desired_min_tx', 'bfd_detect_mult',
                   'bfd_required_min_rx', 'cli_conn_status', 'defaultgw',
                   'description', 'detectprotocol', 'detectserver',
                   'dhcp_client_identifier', 'dhcp_client_status', 'dhcp_expire',
                   'dhcp_relay_ip', 'dhcp_relay_option82', 'dhcp_relay_service',
                   'dhcp_vendor_specific_option', 'distance', 'dns_server_override',
                   'dynamic_dns1', 'dynamic_dns2', 'dynamicgw',
                   'forward_domain', 'gwdetect', 'ha_priority',
                   'icmp_redirect', 'interface', 'ip',
                   'ipv6', 'l2_interface', 'macaddr',
                   'mode', 'mtu', 'mtu_override',
                   'name', 'ping_serv_status', 'priority',
                   'remote_ip', 'secondary_IP', 'secondaryip',
                   'snmp_index', 'speed', 'src_check',
                   'src_check_allow_default', 'status', 'switch',
                   'switch_members', 'type', 'vdom',
                   'vlanforward', 'vlanid', 'vrf',
                   'vrrp', 'vrrp_virtual_mac', 'weight']

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if not data or index == len(path) or path[index] not in data or not data[path[index]]:
        return

    if index == len(path) - 1:
        data[path[index]] = ' '.join(str(elem) for elem in data[path[index]])
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ['allowaccess'],
        ['ipv6', 'ip6_allowaccess'],
        ['secondaryip', 'allowaccess'],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


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


def system_interface(data, fos, check_mode=False):
    state = data['state']
    system_interface_data = data['system_interface']
    system_interface_data = flatten_multilists_attributes(system_interface_data)
    filtered_data = underscore_to_hyphen(filter_system_interface_data(system_interface_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('system', 'interface', filtered_data)
        current_data = fos.get('system', 'interface', mkey=mkey)
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
        return fos.set('system',
                       'interface',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system',
                          'interface',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos, check_mode):
    fos.do_member_operation('system', 'interface')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_interface']:
        resp = system_interface(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_interface'))
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
        "defaultgw": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "defaultgw",
            "help": "Enable/disable default gateway.",
            "category": "unitary"
        },
        "gwdetect": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "gwdetect",
            "help": "Enable/disable gateway detection.",
            "category": "unitary"
        },
        "weight": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "weight",
            "help": "Default weight for static routes if route has no weight configured (0 - 255).",
            "category": "unitary"
        },
        "ip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "ip",
            "help": "Interface IPv4 address.",
            "category": "unitary"
        },
        "vrrp_virtual_mac": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "vrrp-virtual-mac",
            "help": "enable to use virtual MAC for VRRP",
            "category": "unitary"
        },
        "bfd_detect_mult": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "bfd-detect-mult",
            "help": "BFD detection multiplier.",
            "category": "unitary"
        },
        "bfd_required_min_rx": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "bfd-required-min-rx",
            "help": "BFD required minimal receive interval.",
            "category": "unitary"
        },
        "src_check_allow_default": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "src-check-allow-default",
            "help": "Enable/disable.When src ip lookup hits default route,enable means allow pkt else drop.",
            "category": "unitary"
        },
        "dhcp_relay_ip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "dhcp-relay-ip",
            "help": "DHCP relay IP address.",
            "category": "unitary"
        },
        "forward_domain": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "forward-domain",
            "help": "TP mode forward domain.",
            "category": "unitary"
        },
        "speed": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "auto"
                },
                {
                    "value": "10full"
                },
                {
                    "value": "10half"
                },
                {
                    "value": "100full"
                },
                {
                    "value": "100half"
                },
                {
                    "value": "1000full"
                },
                {
                    "value": "1000half"
                },
                {
                    "value": "1000auto"
                }
            ],
            "name": "speed",
            "help": "Speed (copper mode port only).",
            "category": "unitary"
        },
        "vlanforward": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "vlanforward",
            "help": "Enable/disable VLAN forwarding.",
            "category": "unitary"
        },
        "priority": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "priority",
            "help": "Priority of learned routes.",
            "category": "unitary"
        },
        "bfd": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "global"
                },
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "bfd",
            "help": "Bidirectional Forwarding Detection (BFD).",
            "category": "unitary"
        },
        "macaddr": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "macaddr",
            "help": "MAC address.",
            "category": "unitary"
        },
        "bfd_desired_min_tx": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "bfd-desired-min-tx",
            "help": "BFD desired minimal transmit interval.",
            "category": "unitary"
        },
        "switch": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "switch",
            "help": "Contained in switch.",
            "category": "unitary"
        },
        "vlanid": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "vlanid",
            "help": "VLAN ID.",
            "category": "unitary"
        },
        "cli_conn_status": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.4.0"
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "initial"
                },
                {
                    "value": "connecting"
                },
                {
                    "value": "connected"
                },
                {
                    "value": "failed"
                }
            ],
            "name": "cli-conn-status",
            "help": "CLI connection status.",
            "category": "unitary"
        },
        "detectserver": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "detectserver",
            "help": "IP address to PING for gateway detection.",
            "category": "unitary"
        },
        "vrrp": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "status",
                    "help": "Enable/disable status.",
                    "category": "unitary"
                },
                "priority": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "priority",
                    "help": "Priority of the virtual router (1 - 255).",
                    "category": "unitary"
                },
                "adv_interval": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "adv-interval",
                    "help": "Advertisement interval (1 - 255 seconds).",
                    "category": "unitary"
                },
                "start_time": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "start-time",
                    "help": "Startup time (1 - 255 seconds).",
                    "category": "unitary"
                },
                "vrid": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "vrid",
                    "help": "Virtual router identifier (1 - 255).",
                    "category": "unitary"
                },
                "vrgrp": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "vrgrp",
                    "help": "VRRP group ID (1 - 65535).",
                    "category": "unitary"
                },
                "preempt": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "preempt",
                    "help": "Enable/disable preempt mode.",
                    "category": "unitary"
                },
                "version": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "2"
                        },
                        {
                            "value": "3"
                        }
                    ],
                    "name": "version",
                    "help": "VRRP version.",
                    "category": "unitary"
                },
                "vrdst": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "vrdst",
                    "help": "Monitor the route to this destination.",
                    "category": "unitary"
                },
                "vrip": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "vrip",
                    "help": "IP address of the virtual router.",
                    "category": "unitary"
                },
                "backup_vmac_fwd": {
                    "v_range": [
                        [
                            "v7.0.1",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "backup-vmac-fwd",
                    "help": "Enable/disable backup-vmac-fwd.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "vrrp",
            "help": "VRRP configuration",
            "mkey": "vrid",
            "category": "table"
        },
        "allowaccess": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "list",
            "options": [
                {
                    "value": "ping"
                },
                {
                    "value": "https"
                },
                {
                    "value": "http"
                },
                {
                    "value": "ssh"
                },
                {
                    "value": "snmp"
                },
                {
                    "value": "telnet"
                },
                {
                    "value": "radius-acct"
                }
            ],
            "name": "allowaccess",
            "help": "Interface management access.",
            "category": "unitary",
            "elements": "str"
        },
        "dhcp_client_identifier": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "dhcp-client-identifier",
            "help": "DHCP client identifier.",
            "category": "unitary"
        },
        "ping_serv_status": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "ping-serv-status",
            "help": "PING server status.",
            "category": "unitary"
        },
        "type": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "physical"
                },
                {
                    "value": "vlan"
                },
                {
                    "value": "tunnel"
                },
                {
                    "value": "loopback"
                },
                {
                    "value": "switch"
                },
                {
                    "value": "hard-switch"
                },
                {
                    "value": "vap-switch"
                },
                {
                    "value": "hdlc"
                },
                {
                    "value": "vxlan",
                    "v_range": [
                        [
                            "v7.2.1",
                            ""
                        ]
                    ]
                }
            ],
            "name": "type",
            "help": "Interface type.",
            "category": "unitary"
        },
        "snmp_index": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "snmp-index",
            "help": "SNMP index.",
            "category": "unitary"
        },
        "icmp_redirect": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "icmp-redirect",
            "help": "Enable/disable ICMP rediect.",
            "category": "unitary"
        },
        "dhcp_relay_option82": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "disable"
                },
                {
                    "value": "enable"
                }
            ],
            "name": "dhcp-relay-option82",
            "help": "Enable / Disable DHCP relay option-82 insertion.",
            "category": "unitary"
        },
        "description": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "description",
            "help": "Description.",
            "category": "unitary"
        },
        "remote_ip": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "remote-ip",
            "help": "Remote IP address of tunnel.",
            "category": "unitary"
        },
        "dns_server_override": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "dns-server-override",
            "help": "Enable/disable use of DNS server aquired by DHCP or PPPoE.",
            "category": "unitary"
        },
        "secondary_IP": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "secondary-IP",
            "help": "Enable/disable use of secondary IP address.",
            "category": "unitary"
        },
        "vrf": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "vrf",
            "help": "VRF.",
            "category": "unitary"
        },
        "dhcp_expire": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "dhcp_expire",
            "help": "DHCP client expiration.",
            "category": "unitary"
        },
        "interface": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "interface",
            "help": "Interface name.",
            "category": "unitary"
        },
        "dhcp_vendor_specific_option": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "dhcp-vendor-specific-option",
            "help": "DHCP Vendor specific option 43.",
            "category": "unitary"
        },
        "vdom": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "vdom",
            "help": "Virtual domain name.",
            "category": "unitary"
        },
        "dhcp_relay_service": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "disable"
                },
                {
                    "value": "enable"
                }
            ],
            "name": "dhcp-relay-service",
            "help": "Enable/disable use DHCP relay service.",
            "category": "unitary"
        },
        "distance": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "distance",
            "help": "Distance of learned routes.",
            "category": "unitary"
        },
        "name": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "name",
            "help": "Name.",
            "category": "unitary"
        },
        "detectprotocol": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "ping"
                },
                {
                    "value": "tcp-echo"
                },
                {
                    "value": "udp-echo"
                }
            ],
            "name": "detectprotocol",
            "help": "Protocol to use for gateway detection.",
            "category": "unitary"
        },
        "src_check": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "disable"
                },
                {
                    "value": "loose"
                },
                {
                    "value": "strict"
                }
            ],
            "name": "src-check",
            "help": "Enable/disable source IP check.",
            "category": "unitary"
        },
        "ipv6": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "dict",
            "children": {
                "ip6_allowaccess": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "any"
                        },
                        {
                            "value": "ping"
                        },
                        {
                            "value": "https"
                        },
                        {
                            "value": "http"
                        },
                        {
                            "value": "ssh"
                        },
                        {
                            "value": "snmp"
                        },
                        {
                            "value": "telnet"
                        },
                        {
                            "value": "radius-acct"
                        }
                    ],
                    "name": "ip6-allowaccess",
                    "help": "Allow management access to the interface.",
                    "category": "unitary"
                },
                "ip6_retrans_time": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ip6-retrans-time",
                    "help": "IPv6 retransmit time (milliseconds).",
                    "category": "unitary"
                },
                "vrrp6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "status": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable"
                                },
                                {
                                    "value": "disable"
                                }
                            ],
                            "name": "status",
                            "help": "Enable/disable VRRP.",
                            "category": "unitary"
                        },
                        "priority": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "integer",
                            "name": "priority",
                            "help": "Priority of the virtual router (1 - 255).",
                            "category": "unitary"
                        },
                        "vrip6": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "name": "vrip6",
                            "help": "IPv6 address of the virtual router.",
                            "category": "unitary"
                        },
                        "adv_interval": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "integer",
                            "name": "adv-interval",
                            "help": "Advertisement interval (1 - 255 seconds).",
                            "category": "unitary"
                        },
                        "start_time": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "integer",
                            "name": "start-time",
                            "help": "Startup time (1 - 255 seconds).",
                            "category": "unitary"
                        },
                        "vrid": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "integer",
                            "name": "vrid",
                            "help": "Virtual router identifier (1 - 255).",
                            "category": "unitary"
                        },
                        "vrgrp": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "integer",
                            "name": "vrgrp",
                            "help": "VRRP group ID (1 - 65535).",
                            "category": "unitary"
                        },
                        "preempt": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable"
                                },
                                {
                                    "value": "disable"
                                }
                            ],
                            "name": "preempt",
                            "help": "Enable/disable preempt mode.",
                            "category": "unitary"
                        },
                        "accept_mode": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable"
                                },
                                {
                                    "value": "disable"
                                }
                            ],
                            "name": "accept-mode",
                            "help": "Enable/disable accept mode.",
                            "category": "unitary"
                        },
                        "vrdst6": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "name": "vrdst6",
                            "help": "Monitor the route to this destination.",
                            "category": "unitary"
                        }
                    },
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "name": "vrrp6",
                    "help": "IPv6 VRRP configuration.",
                    "mkey": "vrid",
                    "category": "table"
                },
                "ip6_other_flag": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "ip6-other-flag",
                    "help": "Enable/disable sending of IPv6 other flag.",
                    "category": "unitary"
                },
                "ip6_dns_server_override": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "ip6-dns-server-override",
                    "help": "Enable/disable using the DNS server acquired by DHCP.",
                    "category": "unitary"
                },
                "vrip6_link_local": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "vrip6_link_local",
                    "help": "Link-local IPv6 address of virtual router.",
                    "category": "unitary"
                },
                "ip6_address": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "ip6-address",
                    "help": "Primary IPv6 address prefix of interface.",
                    "category": "unitary"
                },
                "ip6_prefix_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "valid_life_time": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "integer",
                            "name": "valid-life-time",
                            "help": "Valid life time (sec).",
                            "category": "unitary"
                        },
                        "prefix": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "name": "prefix",
                            "help": "IPv6 prefix.",
                            "category": "unitary"
                        },
                        "autonomous_flag": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable"
                                },
                                {
                                    "value": "disable"
                                }
                            ],
                            "name": "autonomous-flag",
                            "help": "Enable/disable autonomous flag.",
                            "category": "unitary"
                        },
                        "onlink_flag": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable"
                                },
                                {
                                    "value": "disable"
                                }
                            ],
                            "name": "onlink-flag",
                            "help": "Enable/disable onlink flag.",
                            "category": "unitary"
                        },
                        "preferred_life_time": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "integer",
                            "name": "preferred-life-time",
                            "help": "Preferred life time (sec).",
                            "category": "unitary"
                        }
                    },
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "name": "ip6-prefix-list",
                    "help": "IPv6 advertised prefix list.",
                    "mkey": "prefix",
                    "category": "table"
                },
                "ip6_link_mtu": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ip6-link-mtu",
                    "help": "IPv6 link MTU.",
                    "category": "unitary"
                },
                "ip6_manage_flag": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "ip6-manage-flag",
                    "help": "Enable/disable sending of IPv6 managed flag.",
                    "category": "unitary"
                },
                "ip6_min_interval": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ip6-min-interval",
                    "help": "IPv6 minimum interval (sec) after which RA will be sent.",
                    "category": "unitary"
                },
                "ip6_mode": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "static"
                        },
                        {
                            "value": "dhcp"
                        }
                    ],
                    "name": "ip6-mode",
                    "help": "Addressing mode (static,DHCP).",
                    "category": "unitary"
                },
                "ip6_hop_limit": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ip6-hop-limit",
                    "help": "IPv6 hop limit.",
                    "category": "unitary"
                },
                "ip6_reachable_time": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ip6-reachable-time",
                    "help": "IPv6 reachable time (milliseconds).",
                    "category": "unitary"
                },
                "ip6_extra_addr": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "prefix": {
                            "v_range": [
                                [
                                    "v7.0.0",
                                    ""
                                ]
                            ],
                            "type": "string",
                            "name": "prefix",
                            "help": "IPv6 address prefix.",
                            "category": "unitary"
                        }
                    },
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "name": "ip6-extra-addr",
                    "help": "Extra IPv6 address prefixes of interface.",
                    "mkey": "prefix",
                    "category": "table"
                },
                "ip6_default_life": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ip6-default-life",
                    "help": "IPv6 default life (sec).",
                    "category": "unitary"
                },
                "ip6_max_interval": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ip6-max-interval",
                    "help": "IPv6 maximum interval (sec) after which RA will be sent.",
                    "category": "unitary"
                },
                "vrrp_virtual_mac6": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "vrrp-virtual-mac6",
                    "help": "Enable/disable virtual MAC for VRRP.",
                    "category": "unitary"
                },
                "ip6_unknown_mcast_to_cpu": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "ip6-unknown-mcast-to-cpu",
                    "help": "Enable/disable unknown mcast to cpu.",
                    "category": "unitary"
                },
                "ip6_send_adv": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "ip6-send-adv",
                    "help": "Enable/disable sending of IPv6 Router advertisement.",
                    "category": "unitary"
                },
                "autoconf": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "autoconf",
                    "help": "Enable/disable address automatic config.",
                    "category": "unitary"
                },
                "dhcp6_information_request": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "dhcp6-information-request",
                    "help": "Enable/disable DHCPv6 information request.",
                    "category": "unitary"
                }
            },
            "name": "ipv6",
            "help": "IPv6 address.",
            "category": "complex"
        },
        "dynamicgw": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "dynamicgw",
            "help": "Dynamic gateway.",
            "category": "unitary"
        },
        "mtu_override": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "mtu-override",
            "help": "Enable/disable override of default MTU.",
            "category": "unitary"
        },
        "mtu": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "mtu",
            "help": "Maximum transportation unit (MTU).",
            "category": "unitary"
        },
        "dynamic_dns1": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "dynamic_dns1",
            "help": "Primary dynamic DNS server.",
            "category": "unitary"
        },
        "alias": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "alias",
            "help": "Alias.",
            "category": "unitary"
        },
        "auth_type": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "auto"
                },
                {
                    "value": "pap"
                },
                {
                    "value": "chap"
                },
                {
                    "value": "mschapv1"
                },
                {
                    "value": "mschapv2"
                }
            ],
            "name": "auth-type",
            "help": "PPP authentication type.",
            "category": "unitary"
        },
        "dynamic_dns2": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "dynamic_dns2",
            "help": "Secondary dynamic DNS server.",
            "category": "unitary"
        },
        "status": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "up"
                },
                {
                    "value": "down"
                }
            ],
            "name": "status",
            "help": "Interface status.",
            "category": "unitary"
        },
        "mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "static"
                },
                {
                    "value": "dhcp"
                }
            ],
            "name": "mode",
            "help": "Interface addressing mode.",
            "category": "unitary"
        },
        "ha_priority": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "ha-priority",
            "help": "PING server HA election priority (1 - 50).",
            "category": "unitary"
        },
        "secondaryip": {
            "type": "list",
            "elements": "dict",
            "children": {
                "gwdetect": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "enable"
                        },
                        {
                            "value": "disable"
                        }
                    ],
                    "name": "gwdetect",
                    "help": "Enable/disable gateway detection.",
                    "category": "unitary"
                },
                "detectprotocol": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "ping"
                        },
                        {
                            "value": "tcp-echo"
                        },
                        {
                            "value": "udp-echo"
                        }
                    ],
                    "name": "detectprotocol",
                    "help": "Protocol to use for gateway detection.",
                    "category": "unitary"
                },
                "ip": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "ip",
                    "help": "Interface IPv4 address.",
                    "category": "unitary"
                },
                "detectserver": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "detectserver",
                    "help": "IP address to PING for gateway detection.",
                    "category": "unitary"
                },
                "allowaccess": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "list",
                    "options": [
                        {
                            "value": "ping"
                        },
                        {
                            "value": "https"
                        },
                        {
                            "value": "http"
                        },
                        {
                            "value": "ssh"
                        },
                        {
                            "value": "snmp"
                        },
                        {
                            "value": "telnet"
                        },
                        {
                            "value": "radius-acct"
                        }
                    ],
                    "name": "allowaccess",
                    "help": "Interface management access.",
                    "category": "unitary",
                    "elements": "str"
                },
                "ping_serv_status": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ping-serv-status",
                    "help": "PING server status.",
                    "category": "unitary"
                },
                "ha_priority": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "ha-priority",
                    "help": "PING server HA election priority (1 - 50).",
                    "category": "unitary"
                },
                "id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "id",
                    "help": "Id.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "secondaryip",
            "help": "Second IP address of interface.",
            "mkey": "id",
            "category": "table"
        },
        "switch_members": {
            "type": "list",
            "elements": "dict",
            "children": {
                "member_name": {
                    "v_range": [
                        [
                            "v7.0.0",
                            "v7.0.6"
                        ]
                    ],
                    "type": "string",
                    "name": "member-name",
                    "help": "Interface name.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "name": "switch-members",
            "help": "Switch interfaces.",
            "mkey": "member-name",
            "category": "table"
        },
        "l2_interface": {
            "v_range": [
                [
                    "v7.2.1",
                    ""
                ]
            ],
            "type": "string",
            "name": "l2-interface",
            "help": "L2 interface name.",
            "category": "unitary"
        },
        "dhcp_client_status": {
            "v_range": [
                [
                    "v7.4.1",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "initial"
                },
                {
                    "value": "stopped"
                },
                {
                    "value": "connected"
                },
                {
                    "value": "rebooting"
                },
                {
                    "value": "selecting"
                },
                {
                    "value": "requesting"
                },
                {
                    "value": "binding"
                },
                {
                    "value": "renewing"
                },
                {
                    "value": "rebinding"
                }
            ],
            "name": "dhcp-client-status",
            "help": "DHCP client connection status.",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "name": "interface",
    "help": "Configure interfaces.",
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
        "system_interface": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_interface"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_interface"]['options'][attribute_name]['required'] = True

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=True)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_interface")
        is_error, has_changed, result, diff = fortiswitch_system(module.params, fos, module.check_mode)
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
