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
module: fortiswitch_system_debug
short_description: Application and CLI debug values to set at startup and retain over reboot in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and debug category.
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

    system_debug:
        description:
            - Application and CLI debug values to set at startup and retain over reboot.
        default: null
        type: dict
        suboptions:
            alertd:
                description:
                    - Monitor and Alert daemon.
                type: int
            apache:
                description:
                    - Apache.
                type: int
            auto_script:
                description:
                    - Auto script.
                type: int
            autod:
                description:
                    - Automation Stitches.
                type: int
            bfdd:
                description:
                    - Bidirectional Forwarding Detection (BFD) daemon.
                type: int
            bgpd:
                description:
                    - Bgp daemon.
                type: int
            cli:
                description:
                    - CMDB/CLI debug.
                type: int
            ctrld:
                description:
                    - Switch general control daemon.
                type: int
            cu_swtpd:
                description:
                    - Switch-controller CAPWAP daemon.
                type: int
            delayclid:
                description:
                    - Delay CLI daemon.
                type: int
            dhcp6c:
                description:
                    - DHCPv6 client.
                type: int
            dhcpc:
                description:
                    - DHCP client module.
                type: int
            dhcprelay:
                description:
                    - DHCP relay daemon.
                type: int
            dhcps:
                description:
                    - DHCP server.
                type: int
            dmid:
                description:
                    - DMI daemon debug.
                type: int
            dnsproxy:
                description:
                    - DNS proxy module.
                type: int
            eap_proxy:
                description:
                    - EAP proxy daemon.
                type: int
            email_server:
                description:
                    - Email server.
                type: int
            erspan_auto_mgr:
                description:
                    - ERSPAN-auto mode configuration resolution daemon.
                type: int
            flan_mgr:
                description:
                    - FortiLAN Cloud Manager daemon.
                type: int
            flcmdd:
                description:
                    - FortiLink command daemon.
                type: int
            flow_export:
                description:
                    - Flow-export debug.
                type: int
            fnbamd:
                description:
                    - Fortigate non-blocking auth daemon.
                type: int
            fortilinkd:
                description:
                    - FortiLink daemon.
                type: int
            fpmd:
                description:
                    - FPMD HW routing daemon.
                type: int
            gratarp:
                description:
                    - IP Conflict Gratuitious ARP utility.
                type: int
            gui:
                description:
                    - GUI service.
                type: int
            gvrpd:
                description:
                    - GVRP daemon.
                type: int
            httpsd:
                description:
                    - HTTP/HTTPS daemon.
                type: int
            ip6addrd:
                description:
                    - IPv6 address utility.
                type: int
            ipconflictd:
                description:
                    - IP Conflictd detection daemon.
                type: int
            isisd:
                description:
                    - Isis daemon.
                type: int
            l2d:
                description:
                    - L2 daemon responsible to have core logic to assist L2 feature like MCLAG.
                type: int
            l2dbg:
                description:
                    - Background daemon responsible to assist in any heavy HW related operation needed by L2d.
                type: int
            l3:
                description:
                    - L3 debug.
                type: int
            lacpd:
                description:
                    - Link Aggregation Control Protocol (LACP) debug.
                type: int
            libswitchd:
                description:
                    - Switch library daemon.
                type: int
            link_monitor:
                description:
                    - Link monitor daemon.
                type: int
            lldpmedd:
                description:
                    - Link Layer Discovery Protocol (LLDP) daemon.
                type: int
            macsec_srv:
                description:
                    - MKA/Fortilink macsec cak server daemon.
                type: int
            mcast_snooping:
                description:
                    - Multicast Snooping debug.
                type: int
            miglogd:
                description:
                    - Log daemon.
                type: int
            ntpd:
                description:
                    - Network Time Protocol (NTP) daemon.
                type: int
            nwmcfgd:
                description:
                    - Network monitor daemon responsible for handling configuration.
                type: int
            nwmonitord:
                description:
                    - Network monitor daemon responsible for packet handling and parsing.
                type: int
            ospf6d:
                description:
                    - Open Shortest Path First (OSPFv6) routing daemon.
                type: int
            ospfd:
                description:
                    - Open Shortest Path First (OSPF) routing daemon.
                type: int
            pbrd:
                description:
                    - Policy Based Routing (PBR) routing daemon.
                type: int
            pimd:
                description:
                    - Protocol Independent Multicast (PIM) daemon.
                type: int
            portspeedd:
                description:
                    - Port speed daemon.
                type: int
            radius_das:
                description:
                    - Radius CoA daemon.
                type: int
            radvd:
                description:
                    - router adv daemon
                type: int
            raguard:
                description:
                    - raguard daemon
                type: int
            ripd:
                description:
                    - Routing Information Protocol (RIP) daemon.
                type: int
            ripngd:
                description:
                    - Routing Information Protocol NG (RIPNG) daemon.
                type: int
            router_launcher:
                description:
                    - Routing system launcher daemon.
                type: int
            rsyslogd:
                description:
                    - Remote SYSLOG daemon.
                type: int
            scep:
                description:
                    - SCEP
                type: int
            sflowd:
                description:
                    - sFlow collection and export daemon.
                type: int
            snmpd:
                description:
                    - Simple Network Managment Protocol (SNMP) daemon.
                type: int
            sshd:
                description:
                    - Secure Sockets Shell(SSH) daemon.
                type: int
            staticd:
                description:
                    - Static route daemon.
                type: int
            statsd:
                description:
                    - Stats collection daemon.
                type: int
            stpd:
                description:
                    - Spanning Tree (STP) daemon.
                type: int
            switch_launcher:
                description:
                    - Switching system launcher daemon.
                type: int
            trunkd:
                description:
                    - Link Aggregation Control Protocol (LACP) daemon.
                type: int
            vrrpd:
                description:
                    - Virtual Router Redundancy Protocol (VRRP) daemon.
                type: int
            wiredap:
                description:
                    - Wired AP (802.1X port-based auth) daemon.
                type: int
            wpa_supp:
                description:
                    - MKA/Fortilink macsec daemon.
                type: int
            zebra:
                description:
                    - Zebra routing daemon.
                type: int
"""

EXAMPLES = """
- name: Application and CLI debug values to set at startup and retain over reboot.
  fortinet.fortiswitch.fortiswitch_system_debug:
      system_debug:
          alertd: "3"
          apache: "4"
          auto_script: "5"
          autod: "6"
          bfdd: "7"
          bgpd: "8"
          cli: "4"
          ctrld: "10"
          cu_swtpd: "11"
          delayclid: "12"
          dhcp6c: "13"
          dhcpc: "14"
          dhcprelay: "15"
          dhcps: "16"
          dmid: "17"
          dnsproxy: "18"
          eap_proxy: "19"
          email_server: "20"
          erspan_auto_mgr: "21"
          flan_mgr: "22"
          flcmdd: "23"
          flow_export: "24"
          fnbamd: "25"
          fortilinkd: "26"
          fpmd: "27"
          gratarp: "28"
          gui: "29"
          gvrpd: "30"
          httpsd: "31"
          ip6addrd: "32"
          ipconflictd: "33"
          isisd: "34"
          l2d: "35"
          l2dbg: "36"
          l3: "37"
          lacpd: "38"
          libswitchd: "39"
          link_monitor: "40"
          lldpmedd: "41"
          macsec_srv: "42"
          mcast_snooping: "43"
          miglogd: "44"
          ntpd: "45"
          nwmcfgd: "46"
          nwmonitord: "47"
          ospf6d: "48"
          ospfd: "49"
          pbrd: "50"
          pimd: "51"
          portspeedd: "52"
          radius_das: "53"
          radvd: "54"
          raguard: "55"
          ripd: "56"
          ripngd: "57"
          router_launcher: "58"
          rsyslogd: "59"
          scep: "60"
          sflowd: "61"
          snmpd: "62"
          sshd: "63"
          staticd: "64"
          statsd: "65"
          stpd: "66"
          switch_launcher: "67"
          trunkd: "68"
          vrrpd: "69"
          wiredap: "70"
          wpa_supp: "71"
          zebra: "72"
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


def filter_system_debug_data(json):
    option_list = [
        "alertd",
        "apache",
        "auto_script",
        "autod",
        "bfdd",
        "bgpd",
        "cli",
        "ctrld",
        "cu_swtpd",
        "delayclid",
        "dhcp6c",
        "dhcpc",
        "dhcprelay",
        "dhcps",
        "dmid",
        "dnsproxy",
        "eap_proxy",
        "email_server",
        "erspan_auto_mgr",
        "flan_mgr",
        "flcmdd",
        "flow_export",
        "fnbamd",
        "fortilinkd",
        "fpmd",
        "gratarp",
        "gui",
        "gvrpd",
        "httpsd",
        "ip6addrd",
        "ipconflictd",
        "isisd",
        "l2d",
        "l2dbg",
        "l3",
        "lacpd",
        "libswitchd",
        "link_monitor",
        "lldpmedd",
        "macsec_srv",
        "mcast_snooping",
        "miglogd",
        "ntpd",
        "nwmcfgd",
        "nwmonitord",
        "ospf6d",
        "ospfd",
        "pbrd",
        "pimd",
        "portspeedd",
        "radius_das",
        "radvd",
        "raguard",
        "ripd",
        "ripngd",
        "router_launcher",
        "rsyslogd",
        "scep",
        "sflowd",
        "snmpd",
        "sshd",
        "staticd",
        "statsd",
        "stpd",
        "switch_launcher",
        "trunkd",
        "vrrpd",
        "wiredap",
        "wpa_supp",
        "zebra",
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


def system_debug(data, fos):
    state = data.get("state", None)

    system_debug_data = data["system_debug"]

    filtered_data = filter_system_debug_data(system_debug_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    return fos.set(
        "system",
        "debug",
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


def fortiswitch_system(data, fos):
    fos.do_member_operation("system", "debug")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["system_debug"]:
        resp = system_debug(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_debug"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp) and current_cmdb_index != resp["cmdb-index"],
        resp,
        {},
    )


versioned_schema = {
    "v_range": [],
    "type": "dict",
    "children": {
        "cli": {
            "v_range": [],
            "type": "integer",
            "name": "cli",
            "help": "CMDB/CLI debug.",
            "category": "unitary",
        },
        "radvd": {
            "v_range": [],
            "type": "integer",
            "name": "radvd",
            "help": "router adv daemon",
            "category": "unitary",
        },
        "raguard": {
            "v_range": [],
            "type": "integer",
            "name": "raguard",
            "help": "raguard daemon",
            "category": "unitary",
        },
        "miglogd": {
            "v_range": [],
            "type": "integer",
            "name": "miglogd",
            "help": "Log daemon.",
            "category": "unitary",
        },
        "dhcp6c": {
            "v_range": [],
            "type": "integer",
            "name": "dhcp6c",
            "help": "DHCPv6 client.",
            "category": "unitary",
        },
        "eap_proxy": {
            "v_range": [],
            "type": "integer",
            "name": "eap_proxy",
            "help": "EAP proxy daemon.",
            "category": "unitary",
        },
        "wpa_supp": {
            "v_range": [],
            "type": "integer",
            "name": "wpa_supp",
            "help": "MKA/Fortilink macsec daemon.",
            "category": "unitary",
        },
        "macsec_srv": {
            "v_range": [],
            "type": "integer",
            "name": "macsec_srv",
            "help": "MKA/Fortilink macsec cak server daemon.",
            "category": "unitary",
        },
        "dhcps": {
            "v_range": [],
            "type": "integer",
            "name": "dhcps",
            "help": "DHCP server.",
            "category": "unitary",
        },
        "fnbamd": {
            "v_range": [],
            "type": "integer",
            "name": "fnbamd",
            "help": "Fortigate non-blocking auth daemon.",
            "category": "unitary",
        },
        "dhcprelay": {
            "v_range": [],
            "type": "integer",
            "name": "dhcprelay",
            "help": "DHCP relay daemon.",
            "category": "unitary",
        },
        "snmpd": {
            "v_range": [],
            "type": "integer",
            "name": "snmpd",
            "help": "Simple Network Managment Protocol (SNMP) daemon.",
            "category": "unitary",
        },
        "dnsproxy": {
            "v_range": [],
            "type": "integer",
            "name": "dnsproxy",
            "help": "DNS proxy module.",
            "category": "unitary",
        },
        "sflowd": {
            "v_range": [],
            "type": "integer",
            "name": "sflowd",
            "help": "sFlow collection and export daemon.",
            "category": "unitary",
        },
        "dhcpc": {
            "v_range": [],
            "type": "integer",
            "name": "dhcpc",
            "help": "DHCP client module.",
            "category": "unitary",
        },
        "router_launcher": {
            "v_range": [],
            "type": "integer",
            "name": "router-launcher",
            "help": "Routing system launcher daemon.",
            "category": "unitary",
        },
        "sshd": {
            "v_range": [],
            "type": "integer",
            "name": "sshd",
            "help": "Secure Sockets Shell(SSH) daemon.",
            "category": "unitary",
        },
        "ctrld": {
            "v_range": [],
            "type": "integer",
            "name": "ctrld",
            "help": "Switch general control daemon.",
            "category": "unitary",
        },
        "stpd": {
            "v_range": [],
            "type": "integer",
            "name": "stpd",
            "help": "Spanning Tree (STP) daemon.",
            "category": "unitary",
        },
        "trunkd": {
            "v_range": [],
            "type": "integer",
            "name": "trunkd",
            "help": "Link Aggregation Control Protocol (LACP) daemon.",
            "category": "unitary",
        },
        "lacpd": {
            "v_range": [],
            "type": "integer",
            "name": "lacpd",
            "help": "Link Aggregation Control Protocol (LACP) debug.",
            "category": "unitary",
        },
        "lldpmedd": {
            "v_range": [],
            "type": "integer",
            "name": "lldpmedd",
            "help": "Link Layer Discovery Protocol (LLDP) daemon.",
            "category": "unitary",
        },
        "ipconflictd": {
            "v_range": [],
            "type": "integer",
            "name": "ipconflictd",
            "help": "IP Conflictd detection daemon.",
            "category": "unitary",
        },
        "httpsd": {
            "v_range": [],
            "type": "integer",
            "name": "httpsd",
            "help": "HTTP/HTTPS daemon.",
            "category": "unitary",
        },
        "link_monitor": {
            "v_range": [],
            "type": "integer",
            "name": "link-monitor",
            "help": "Link monitor daemon.",
            "category": "unitary",
        },
        "libswitchd": {
            "v_range": [],
            "type": "integer",
            "name": "libswitchd",
            "help": "Switch library daemon.",
            "category": "unitary",
        },
        "switch_launcher": {
            "v_range": [],
            "type": "integer",
            "name": "switch-launcher",
            "help": "Switching system launcher daemon.",
            "category": "unitary",
        },
        "alertd": {
            "v_range": [],
            "type": "integer",
            "name": "alertd",
            "help": "Monitor and Alert daemon.",
            "category": "unitary",
        },
        "l2d": {
            "v_range": [],
            "type": "integer",
            "name": "l2d",
            "help": "L2 daemon responsible to have core logic to assist L2 feature like MCLAG.",
            "category": "unitary",
        },
        "l2dbg": {
            "v_range": [],
            "type": "integer",
            "name": "l2dbg",
            "help": "Background daemon responsible to assist in any heavy HW related operation needed by L2d.",
            "category": "unitary",
        },
        "nwmcfgd": {
            "v_range": [],
            "type": "integer",
            "name": "nwmcfgd",
            "help": "Network monitor daemon responsible for handling configuration.",
            "category": "unitary",
        },
        "nwmonitord": {
            "v_range": [],
            "type": "integer",
            "name": "nwmonitord",
            "help": "Network monitor daemon responsible for packet handling and parsing.",
            "category": "unitary",
        },
        "portspeedd": {
            "v_range": [],
            "type": "integer",
            "name": "portspeedd",
            "help": "Port speed daemon.",
            "category": "unitary",
        },
        "l3": {
            "v_range": [],
            "type": "integer",
            "name": "l3",
            "help": "L3 debug.",
            "category": "unitary",
        },
        "mcast_snooping": {
            "v_range": [],
            "type": "integer",
            "name": "mcast-snooping",
            "help": "Multicast Snooping debug.",
            "category": "unitary",
        },
        "dmid": {
            "v_range": [],
            "type": "integer",
            "name": "dmid",
            "help": "DMI daemon debug.",
            "category": "unitary",
        },
        "scep": {
            "v_range": [],
            "type": "integer",
            "name": "scep",
            "help": "SCEP",
            "category": "unitary",
        },
        "cu_swtpd": {
            "v_range": [],
            "type": "integer",
            "name": "cu_swtpd",
            "help": "Switch-controller CAPWAP daemon.",
            "category": "unitary",
        },
        "fortilinkd": {
            "v_range": [],
            "type": "integer",
            "name": "fortilinkd",
            "help": "FortiLink daemon.",
            "category": "unitary",
        },
        "flcmdd": {
            "v_range": [],
            "type": "integer",
            "name": "flcmdd",
            "help": "FortiLink command daemon.",
            "category": "unitary",
        },
        "gvrpd": {
            "v_range": [],
            "type": "integer",
            "name": "gvrpd",
            "help": "GVRP daemon.",
            "category": "unitary",
        },
        "flan_mgr": {
            "v_range": [],
            "type": "integer",
            "name": "flan-mgr",
            "help": "FortiLAN Cloud Manager daemon.",
            "category": "unitary",
        },
        "rsyslogd": {
            "v_range": [],
            "type": "integer",
            "name": "rsyslogd",
            "help": "Remote SYSLOG daemon.",
            "category": "unitary",
        },
        "vrrpd": {
            "v_range": [],
            "type": "integer",
            "name": "vrrpd",
            "help": "Virtual Router Redundancy Protocol (VRRP) daemon.",
            "category": "unitary",
        },
        "fpmd": {
            "v_range": [],
            "type": "integer",
            "name": "fpmd",
            "help": "FPMD HW routing daemon.",
            "category": "unitary",
        },
        "ospfd": {
            "v_range": [],
            "type": "integer",
            "name": "ospfd",
            "help": "Open Shortest Path First (OSPF) routing daemon.",
            "category": "unitary",
        },
        "ospf6d": {
            "v_range": [],
            "type": "integer",
            "name": "ospf6d",
            "help": "Open Shortest Path First (OSPFv6) routing daemon.",
            "category": "unitary",
        },
        "pbrd": {
            "v_range": [],
            "type": "integer",
            "name": "pbrd",
            "help": "Policy Based Routing (PBR) routing daemon.",
            "category": "unitary",
        },
        "isisd": {
            "v_range": [],
            "type": "integer",
            "name": "isisd",
            "help": "Isis daemon.",
            "category": "unitary",
        },
        "ripd": {
            "v_range": [],
            "type": "integer",
            "name": "ripd",
            "help": "Routing Information Protocol (RIP) daemon.",
            "category": "unitary",
        },
        "ripngd": {
            "v_range": [],
            "type": "integer",
            "name": "ripngd",
            "help": "Routing Information Protocol NG (RIPNG) daemon.",
            "category": "unitary",
        },
        "bgpd": {
            "v_range": [],
            "type": "integer",
            "name": "bgpd",
            "help": "Bgp daemon.",
            "category": "unitary",
        },
        "zebra": {
            "v_range": [],
            "type": "integer",
            "name": "zebra",
            "help": "Zebra routing daemon.",
            "category": "unitary",
        },
        "bfdd": {
            "v_range": [],
            "type": "integer",
            "name": "bfdd",
            "help": "Bidirectional Forwarding Detection (BFD) daemon.",
            "category": "unitary",
        },
        "staticd": {
            "v_range": [],
            "type": "integer",
            "name": "staticd",
            "help": "Static route daemon.",
            "category": "unitary",
        },
        "pimd": {
            "v_range": [],
            "type": "integer",
            "name": "pimd",
            "help": "Protocol Independent Multicast (PIM) daemon.",
            "category": "unitary",
        },
        "ntpd": {
            "v_range": [],
            "type": "integer",
            "name": "ntpd",
            "help": "Network Time Protocol (NTP) daemon.",
            "category": "unitary",
        },
        "wiredap": {
            "v_range": [],
            "type": "integer",
            "name": "wiredap",
            "help": "Wired AP (802.1X port-based auth) daemon.",
            "category": "unitary",
        },
        "ip6addrd": {
            "v_range": [],
            "type": "integer",
            "name": "ip6addrd",
            "help": "IPv6 address utility.",
            "category": "unitary",
        },
        "gratarp": {
            "v_range": [],
            "type": "integer",
            "name": "gratarp",
            "help": "IP Conflict Gratuitious ARP utility.",
            "category": "unitary",
        },
        "radius_das": {
            "v_range": [],
            "type": "integer",
            "name": "radius_das",
            "help": "Radius CoA daemon.",
            "category": "unitary",
        },
        "gui": {
            "v_range": [],
            "type": "integer",
            "name": "gui",
            "help": "GUI service.",
            "category": "unitary",
        },
        "statsd": {
            "v_range": [],
            "type": "integer",
            "name": "statsd",
            "help": "Stats collection daemon.",
            "category": "unitary",
        },
        "flow_export": {
            "v_range": [],
            "type": "integer",
            "name": "flow-export",
            "help": "Flow-export debug.",
            "category": "unitary",
        },
        "erspan_auto_mgr": {
            "v_range": [],
            "type": "integer",
            "name": "erspan-auto-mgr",
            "help": "ERSPAN-auto mode configuration resolution daemon.",
            "category": "unitary",
        },
        "autod": {
            "v_range": [],
            "type": "integer",
            "name": "autod",
            "help": "Automation Stitches.",
            "category": "unitary",
        },
        "email_server": {
            "v_range": [],
            "type": "integer",
            "name": "email-server",
            "help": "Email server.",
            "category": "unitary",
        },
        "auto_script": {
            "v_range": [],
            "type": "integer",
            "name": "auto-script",
            "help": "Auto script.",
            "category": "unitary",
        },
        "apache": {
            "v_range": [],
            "type": "integer",
            "name": "apache",
            "help": "Apache.",
            "category": "unitary",
        },
        "delayclid": {
            "v_range": [],
            "type": "integer",
            "name": "delayclid",
            "help": "Delay CLI daemon.",
            "category": "unitary",
        },
    },
    "name": "debug",
    "help": "Application and CLI debug values to set at startup and retain over reboot.",
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
        "system_debug": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_debug"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_debug"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)

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
            fos, versioned_schema, "system_debug"
        )
        is_error, has_changed, result, diff = fortiswitch_system(module.params, fos)
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
