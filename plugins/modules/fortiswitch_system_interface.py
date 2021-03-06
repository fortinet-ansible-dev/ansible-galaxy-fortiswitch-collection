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
module: fortiswitch_system_interface
short_description: Configure interfaces in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and interface category.
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
                type: str
                choices:
                    - ping
                    - https
                    - http
                    - ssh
                    - snmp
                    - telnet
                    - radius-acct
            auth_type:
                description:
                    - PPP authentication type.
                type: str
                choices:
                    - auto
                    - pap
                    - chap
                    - mschapv1
                    - mschapv2
            bfd:
                description:
                    - Bidirectional Forwarding Detection (BFD).
                type: str
                choices:
                    - global
                    - enable
                    - disable
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
                    - initial
                    - connecting
                    - connected
                    - failed
            defaultgw:
                description:
                    - Enable/disable default gateway.
                type: str
                choices:
                    - enable
                    - disable
            description:
                description:
                    - Description.
                type: str
            detectprotocol:
                description:
                    - Protocol to use for gateway detection.
                type: str
                choices:
                    - ping
                    - tcp-echo
                    - udp-echo
            detectserver:
                description:
                    - IP address to PING for gateway detection.
                type: str
            dhcp_client_identifier:
                description:
                    - DHCP client identifier.
                type: str
            dhcp_relay_ip:
                description:
                    - DHCP relay IP address.
                type: str
            dhcp_relay_option82:
                description:
                    - Enable / Disable DHCP relay option-82 insertion.
                type: str
                choices:
                    - disable
                    - enable
            dhcp_relay_service:
                description:
                    - Enable/disable use DHCP relay service.
                type: str
                choices:
                    - disable
                    - enable
            dhcp_vendor_specific_option:
                description:
                    - DHCP Vendor specific option 43.
                type: str
            dhcp_expire:
                description:
                    - DHCP client expiration.
                type: int
            distance:
                description:
                    - Distance of learned routes.
                type: int
            dns_server_override:
                description:
                    - Enable/disable use of DNS server aquired by DHCP or PPPoE.
                type: str
                choices:
                    - enable
                    - disable
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
                    - enable
                    - disable
            ha_priority:
                description:
                    - PING server HA election priority (1 - 50).
                type: int
            icmp_redirect:
                description:
                    - Enable/disable ICMP rediect.
                type: str
                choices:
                    - enable
                    - disable
            interface:
                description:
                    - Interface name. Source system.interface.name.
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
                            - enable
                            - disable
                    dhcp6_information_request:
                        description:
                            - Enable/disable DHCPv6 information request.
                        type: str
                        choices:
                            - enable
                            - disable
                    ip6_address:
                        description:
                            - Primary IPv6 address prefix of interface.
                        type: str
                    ip6_allowaccess:
                        description:
                            - Allow management access to the interface.
                        type: str
                        choices:
                            - any
                            - ping
                            - https
                            - http
                            - ssh
                            - snmp
                            - telnet
                            - radius-acct
                    ip6_default_life:
                        description:
                            - IPv6 default life (sec).
                        type: int
                    ip6_dns_server_override:
                        description:
                            - Enable/disable using the DNS server acquired by DHCP.
                        type: str
                        choices:
                            - enable
                            - disable
                    ip6_extra_addr:
                        description:
                            - Extra IPv6 address prefixes of interface.
                        type: list
                        suboptions:
                            prefix:
                                description:
                                    - IPv6 address prefix.
                                required: true
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
                            - enable
                            - disable
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
                            - static
                            - dhcp
                    ip6_other_flag:
                        description:
                            - Enable/disable sending of IPv6 other flag.
                        type: str
                        choices:
                            - enable
                            - disable
                    ip6_prefix_list:
                        description:
                            - IPv6 advertised prefix list.
                        type: list
                        suboptions:
                            autonomous_flag:
                                description:
                                    - Enable/disable autonomous flag.
                                type: str
                                choices:
                                    - enable
                                    - disable
                            onlink_flag:
                                description:
                                    - Enable/disable onlink flag.
                                type: str
                                choices:
                                    - enable
                                    - disable
                            preferred_life_time:
                                description:
                                    - Preferred life time (sec).
                                type: int
                            prefix:
                                description:
                                    - IPv6 prefix.
                                required: true
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
                            - enable
                            - disable
                    ip6_unknown_mcast_to_cpu:
                        description:
                            - Enable/disable unknown mcast to cpu.
                        type: str
                        choices:
                            - enable
                            - disable
                    vrip6_link_local:
                        description:
                            - Link-local IPv6 address of virtual router.
                        type: str
                    vrrp_virtual_mac6:
                        description:
                            - Enable/disable virtual MAC for VRRP.
                        type: str
                        choices:
                            - enable
                            - disable
                    vrrp6:
                        description:
                            - IPv6 VRRP configuration.
                        type: list
                        suboptions:
                            accept_mode:
                                description:
                                    - Enable/disable accept mode.
                                type: str
                                choices:
                                    - enable
                                    - disable
                            adv_interval:
                                description:
                                    - Advertisement interval (1 - 255 seconds).
                                type: int
                            preempt:
                                description:
                                    - Enable/disable preempt mode.
                                type: str
                                choices:
                                    - enable
                                    - disable
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
                                    - enable
                                    - disable
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
                                required: true
                                type: int
                            vrip6:
                                description:
                                    - IPv6 address of the virtual router.
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
                    - static
                    - dhcp
            mtu:
                description:
                    - Maximum transportation unit (MTU).
                type: int
            mtu_override:
                description:
                    - Enable/disable override of default MTU.
                type: str
                choices:
                    - enable
                    - disable
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
                    - enable
                    - disable
            secondaryip:
                description:
                    - Second IP address of interface.
                type: list
                suboptions:
                    allowaccess:
                        description:
                            - Interface management access.
                        type: str
                        choices:
                            - ping
                            - https
                            - http
                            - ssh
                            - snmp
                            - telnet
                            - radius-acct
                    detectprotocol:
                        description:
                            - Protocol to use for gateway detection.
                        type: str
                        choices:
                            - ping
                            - tcp-echo
                            - udp-echo
                    detectserver:
                        description:
                            - IP address to PING for gateway detection.
                        type: str
                    gwdetect:
                        description:
                            - Enable/disable gateway detection.
                        type: str
                        choices:
                            - enable
                            - disable
                    ha_priority:
                        description:
                            - PING server HA election priority (1 - 50).
                        type: int
                    id:
                        description:
                            - Id.
                        required: true
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
                    - auto
                    - 10full
                    - 10half
                    - 100full
                    - 100half
                    - 1000full
                    - 1000half
                    - 1000auto
            src_check:
                description:
                    - Enable/disable source IP check.
                type: str
                choices:
                    - disable
                    - loose
                    - strict
            src_check_allow_default:
                description:
                    - Enable/disable.When src ip lookup hits default route,enable means allow pkt else drop.
                type: str
                choices:
                    - enable
                    - disable
            status:
                description:
                    - Interface status.
                type: str
                choices:
                    - up
                    - down
            switch:
                description:
                    - Contained in switch.
                type: str
            switch_members:
                description:
                    - Switch interfaces.
                type: list
                suboptions:
                    member_name:
                        description:
                            - Interface name. Source switch.interface.name.
                        type: str
            type:
                description:
                    - Interface type.
                type: str
                choices:
                    - physical
                    - vlan
                    - tunnel
                    - loopback
                    - switch
                    - hard-switch
                    - vap-switch
                    - hdlc
            vdom:
                description:
                    - Virtual domain name. Source system.vdom.name.
                type: str
            vlanforward:
                description:
                    - Enable/disable VLAN forwarding.
                type: str
                choices:
                    - enable
                    - disable
            vlanid:
                description:
                    - VLAN ID.
                type: int
            vrf:
                description:
                    - VRF. Source router.vrf.name.
                type: str
            vrrp:
                description:
                    - VRRP configuration
                type: list
                suboptions:
                    adv_interval:
                        description:
                            - Advertisement interval (1 - 255 seconds).
                        type: int
                    preempt:
                        description:
                            - Enable/disable preempt mode.
                        type: str
                        choices:
                            - enable
                            - disable
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
                            - enable
                            - disable
                    version:
                        description:
                            - VRRP version.
                        type: str
                        choices:
                            - 2
                            - 3
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
                        required: true
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
                    - enable
                    - disable
            weight:
                description:
                    - Default weight for static routes if route has no weight configured (0 - 255).
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
  - name: Configure interfaces.
    fortiswitch_system_interface:
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
        dhcp_client_identifier:  "myId_15"
        dhcp_relay_ip: "<your_own_value>"
        dhcp_relay_option82: "disable"
        dhcp_relay_service: "disable"
        dhcp_vendor_specific_option: "<your_own_value>"
        dhcp_expire: "20"
        distance: "21"
        dns_server_override: "enable"
        dynamic_dns1: "<your_own_value>"
        dynamic_dns2: "<your_own_value>"
        dynamicgw: "<your_own_value>"
        forward_domain: "26"
        gwdetect: "enable"
        ha_priority: "28"
        icmp_redirect: "enable"
        interface: "<your_own_value> (source system.interface.name)"
        ip: "<your_own_value>"
        ipv6:
            autoconf: "enable"
            dhcp6_information_request: "enable"
            ip6_address: "<your_own_value>"
            ip6_allowaccess: "any"
            ip6_default_life: "37"
            ip6_dns_server_override: "enable"
            ip6_extra_addr:
             -
                prefix: "<your_own_value>"
            ip6_hop_limit: "41"
            ip6_link_mtu: "42"
            ip6_manage_flag: "enable"
            ip6_max_interval: "44"
            ip6_min_interval: "45"
            ip6_mode: "static"
            ip6_other_flag: "enable"
            ip6_prefix_list:
             -
                autonomous_flag: "enable"
                onlink_flag: "enable"
                preferred_life_time: "51"
                prefix: "<your_own_value>"
                valid_life_time: "53"
            ip6_reachable_time: "54"
            ip6_retrans_time: "55"
            ip6_send_adv: "enable"
            ip6_unknown_mcast_to_cpu: "enable"
            vrip6_link_local: "<your_own_value>"
            vrrp_virtual_mac6: "enable"
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
        macaddr: "<your_own_value>"
        mode: "static"
        mtu: "73"
        mtu_override: "enable"
        name: "default_name_75"
        ping_serv_status: "76"
        priority: "77"
        remote_ip: "<your_own_value>"
        secondary_IP: "enable"
        secondaryip:
         -
            allowaccess: "ping"
            detectprotocol: "ping"
            detectserver: "<your_own_value>"
            gwdetect: "enable"
            ha_priority: "85"
            id:  "86"
            ip: "<your_own_value>"
            ping_serv_status: "88"
        snmp_index: "89"
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
        vlanid: "100"
        vrf: "<your_own_value> (source router.vrf.name)"
        vrrp:
         -
            adv_interval: "103"
            preempt: "enable"
            priority: "105"
            start_time: "106"
            status: "enable"
            version: "2"
            vrdst: "<your_own_value>"
            vrgrp: "110"
            vrid: "111"
            vrip: "<your_own_value>"
        vrrp_virtual_mac: "enable"
        weight: "114"

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


def filter_system_interface_data(json):
    option_list = ['alias', 'allowaccess', 'auth_type',
                   'bfd', 'bfd_desired_min_tx', 'bfd_detect_mult',
                   'bfd_required_min_rx', 'cli_conn_status', 'defaultgw',
                   'description', 'detectprotocol', 'detectserver',
                   'dhcp_client_identifier', 'dhcp_relay_ip', 'dhcp_relay_option82',
                   'dhcp_relay_service', 'dhcp_vendor_specific_option', 'dhcp_expire',
                   'distance', 'dns_server_override', 'dynamic_dns1',
                   'dynamic_dns2', 'dynamicgw', 'forward_domain',
                   'gwdetect', 'ha_priority', 'icmp_redirect',
                   'interface', 'ip', 'ipv6',
                   'macaddr', 'mode', 'mtu',
                   'mtu_override', 'name', 'ping_serv_status',
                   'priority', 'remote_ip', 'secondary_IP',
                   'secondaryip', 'snmp_index', 'speed',
                   'src_check', 'src_check_allow_default', 'status',
                   'switch', 'switch_members', 'type',
                   'vdom', 'vlanforward', 'vlanid',
                   'vrf', 'vrrp', 'vrrp_virtual_mac',
                   'weight']
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


def system_interface(data, fos):

    state = data['state']

    system_interface_data = data['system_interface']
    filtered_data = underscore_to_hyphen(filter_system_interface_data(system_interface_data))

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


def fortiswitch_system(data, fos):

    fos.do_member_operation('system_interface')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_interface']:
        resp = system_interface(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_interface'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "auth_type": {
            "type": "string",
            "options": [
                {
                    "value": "auto",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "pap",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "chap",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "mschapv1",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "mschapv2",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "status": {
            "type": "string",
            "options": [
                {
                    "value": "up",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "down",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "gwdetect": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "dhcp_relay_option82": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "weight": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "mtu_override": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "ip": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "ha_priority": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "cli_conn_status": {
            "type": "string",
            "options": [
                {
                    "value": "initial",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "connecting",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "connected",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "failed",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "ping_serv_status": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "src_check": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "loose",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "strict",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "dhcp_vendor_specific_option": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "speed": {
            "type": "string",
            "options": [
                {
                    "value": "auto",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "10full",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "10half",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "100full",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "100half",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "1000full",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "1000half",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "1000auto",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "vlanforward": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "icmp_redirect": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "forward_domain": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "priority": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "secondary_IP": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "bfd": {
            "type": "string",
            "options": [
                {
                    "value": "global",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "switch_members": {
            "type": "list",
            "children": {
                "member_name": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        },
        "vlanid": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "bfd_desired_min_tx": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "detectserver": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "vrrp": {
            "type": "list",
            "children": {
                "status": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vrgrp": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "start_time": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vrid": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "priority": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "adv_interval": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "preempt": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "version": {
                    "type": "string",
                    "options": [
                        {
                            "value": "2",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "3",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vrdst": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vrip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        },
        "allowaccess": {
            "type": "string",
            "options": [
                {
                    "value": "ping",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "https",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "http",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ssh",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "snmp",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "telnet",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "radius-acct",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "ipv6": {
            "type": "dict",
            "children": {
                "ip6_dns_server_override": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_other_flag": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vrrp6": {
                    "type": "list",
                    "children": {
                        "status": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "vrgrp": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "vrip6": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "start_time": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "vrid": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "priority": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "adv_interval": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "preempt": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "vrdst6": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "accept_mode": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_extra_addr": {
                    "type": "list",
                    "children": {
                        "prefix": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_unknown_mcast_to_cpu": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_address": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vrip6_link_local": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_prefix_list": {
                    "type": "list",
                    "children": {
                        "prefix": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "valid_life_time": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "onlink_flag": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "autonomous_flag": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "preferred_life_time": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_retrans_time": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_manage_flag": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_max_interval": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "dhcp6_information_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_link_mtu": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "static",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "dhcp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_hop_limit": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vrrp_virtual_mac6": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_send_adv": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_default_life": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "autoconf": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_allowaccess": {
                    "type": "string",
                    "options": [
                        {
                            "value": "any",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "ping",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "https",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "http",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "ssh",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "snmp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "telnet",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "radius-acct",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_min_interval": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip6_reachable_time": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        },
        "dhcp_client_identifier": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "type": {
            "type": "string",
            "options": [
                {
                    "value": "physical",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "vlan",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "tunnel",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "loopback",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "switch",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "hard-switch",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "vap-switch",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "hdlc",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "remote_ip": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "defaultgw": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "bfd_required_min_rx": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "snmp_index": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "description": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "dns_server_override": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "alias": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "vrf": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "dhcp_expire": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "interface": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "dhcp_relay_service": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "src_check_allow_default": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "vdom": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "distance": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "detectprotocol": {
            "type": "string",
            "options": [
                {
                    "value": "ping",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "tcp-echo",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "udp-echo",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "bfd_detect_mult": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "dynamicgw": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "vrrp_virtual_mac": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "mtu": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "macaddr": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "dynamic_dns1": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "switch": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "dynamic_dns2": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "dhcp_relay_ip": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "mode": {
            "type": "string",
            "options": [
                {
                    "value": "static",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "dhcp",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "secondaryip": {
            "type": "list",
            "children": {
                "gwdetect": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "detectprotocol": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ping",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tcp-echo",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "udp-echo",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "detectserver": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ping_serv_status": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "allowaccess": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ping",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "https",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "http",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "ssh",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "snmp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "telnet",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "radius-acct",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ha_priority": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        }
    },
    "revisions": {
        "v7.0.0": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'name'
    fields = {
        "enable_log": {"required": False, "type": bool},
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
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_interface"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_interface"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_interface")

        is_error, has_changed, result = fortiswitch_system(module.params, fos)

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
