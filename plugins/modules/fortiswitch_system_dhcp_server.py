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
module: fortiswitch_system_dhcp_server
short_description: Configure DHCP servers in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system_dhcp feature and server category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v7.0.0
version_added: "1.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
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
    system_dhcp_server:
        description:
            - Configure DHCP servers.
        default: null
        type: dict
        suboptions:
            auto_configuration:
                description:
                    - Enable/disable auto configuration.
                type: str
                choices:
                    - disable
                    - enable
            conflicted_ip_timeout:
                description:
                    - Time in seconds to wait after a conflicted IP address is removed from the DHCP range before it can be reused.
                type: int
            default_gateway:
                description:
                    - Default gateway IP address assigned by the DHCP server.
                type: str
            dns_server1:
                description:
                    - DNS server 1.
                type: str
            dns_server2:
                description:
                    - DNS server 2.
                type: str
            dns_server3:
                description:
                    - DNS server 3.
                type: str
            dns_service:
                description:
                    - Options for assigning DNS servers to DHCP clients.
                type: str
                choices:
                    - local
                    - default
                    - specify
            domain:
                description:
                    - Domain name suffix for the IP addresses that the DHCP server assigns to clients.
                type: str
            exclude_range:
                description:
                    - Exclude one or more ranges of IP addresses from being assigned to clients.
                type: list
                elements: dict
                suboptions:
                    end_ip:
                        description:
                            - End of IP range.
                        type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    start_ip:
                        description:
                            - Start of IP range.
                        type: str
            filename:
                description:
                    - Name of the boot file on the TFTP server.
                type: str
            id:
                description:
                    - ID.
                required: true
                type: int
            interface:
                description:
                    - DHCP server can assign IP configurations to clients connected to this interface. Source system.interface.name.
                type: str
            ip_mode:
                description:
                    - Method used to assign client IP.
                type: str
                choices:
                    - range
                    - usrgrp
            ip_range:
                description:
                    - DHCP IP range configuration.
                type: list
                elements: dict
                suboptions:
                    end_ip:
                        description:
                            - End of IP range.
                        type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    start_ip:
                        description:
                            - Start of IP range.
                        type: str
            lease_time:
                description:
                    - Lease time in seconds, 0 means unlimited.
                type: int
            netmask:
                description:
                    - Netmask assigned by the DHCP server.
                type: str
            next_server:
                description:
                    - IP address of a server (for example, a TFTP sever) that DHCP clients can download a boot file from.
                type: str
            ntp_server1:
                description:
                    - NTP server 1.
                type: str
            ntp_server2:
                description:
                    - NTP server 2.
                type: str
            ntp_server3:
                description:
                    - NTP server 3.
                type: str
            ntp_service:
                description:
                    - Options for assigning Network Time Protocol (NTP) servers to DHCP clients.
                type: str
                choices:
                    - local
                    - default
                    - specify
            options:
                description:
                    - DHCP options.
                type: list
                elements: dict
                suboptions:
                    code:
                        description:
                            - DHCP option code.
                        type: int
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    ip:
                        description:
                            - DHCP option IPs.
                        type: str
                    type:
                        description:
                            - DHCP option type.
                        type: str
                        choices:
                            - hex
                            - string
                            - ip
                            - fqdn
                    value:
                        description:
                            - DHCP option value.
                        type: str
            reserved_address:
                description:
                    - Options for the DHCP server to assign IP settings to specific MAC addresses.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Options for the DHCP server to configure the client with the reserved MAC address.
                        type: str
                        choices:
                            - assign
                            - block
                            - reserved
                    circuit_id:
                        description:
                            - Option 82 circuit-ID of the client that will get the reserved IP address.
                        type: str
                    circuit_id_type:
                        description:
                            - DHCP option type.
                        type: str
                        choices:
                            - hex
                            - string
                    description:
                        description:
                            - Description.
                        type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    ip:
                        description:
                            - IP address to be reserved for the MAC address.
                        type: str
                    mac:
                        description:
                            - MAC address of the client that will get the reserved IP address.
                        type: str
                    remote_id:
                        description:
                            - Option 82 remote-ID of the client that will get the reserved IP address.
                        type: str
                    remote_id_type:
                        description:
                            - DHCP option type.
                        type: str
                        choices:
                            - hex
                            - string
                    type:
                        description:
                            - DHCP reserved-address type.
                        type: str
                        choices:
                            - mac
                            - option82
            server_type:
                description:
                    - DHCP server can be a normal DHCP server or an IPsec DHCP server.
                type: str
                choices:
                    - regular
            status:
                description:
                    - Enable/disable this DHCP configuration.
                type: str
                choices:
                    - disable
                    - enable
            tftp_server:
                description:
                    - One or more hostnames or IP addresses of the TFTP servers in quotes separated by spaces.
                type: list
                elements: dict
                suboptions:
                    tftp_server:
                        description:
                            - TFTP server.
                        type: str
            timezone:
                description:
                    - Select the time zone to be assigned to DHCP clients.
                type: str
                choices:
                    - 01
                    - 02
                    - 03
                    - 04
                    - 05
                    - 81
                    - 06
                    - 07
                    - 08
                    - 09
                    - 10
                    - 11
                    - 12
                    - 13
                    - 74
                    - 14
                    - 77
                    - 15
                    - 87
                    - 16
                    - 17
                    - 18
                    - 19
                    - 20
                    - 75
                    - 21
                    - 22
                    - 23
                    - 24
                    - 80
                    - 79
                    - 25
                    - 26
                    - 27
                    - 28
                    - 78
                    - 29
                    - 30
                    - 31
                    - 32
                    - 33
                    - 34
                    - 35
                    - 36
                    - 37
                    - 38
                    - 83
                    - 84
                    - 40
                    - 85
                    - 41
                    - 42
                    - 43
                    - 39
                    - 44
                    - 46
                    - 47
                    - 51
                    - 48
                    - 45
                    - 49
                    - 50
                    - 52
                    - 53
                    - 54
                    - 55
                    - 56
                    - 57
                    - 58
                    - 59
                    - 60
                    - 62
                    - 63
                    - 61
                    - 64
                    - 65
                    - 66
                    - 67
                    - 68
                    - 69
                    - 70
                    - 71
                    - 72
                    - 00
                    - 82
                    - 73
                    - 86
                    - 76
            timezone_option:
                description:
                    - Options for the DHCP server to set the client"s time zone.
                type: str
                choices:
                    - disable
                    - default
                    - specify
            vci_match:
                description:
                    - Enable/disable vendor class identifier (VCI) matching. When enabled only DHCP requests with a matching VCI are served.
                type: str
                choices:
                    - disable
                    - enable
            vci_string:
                description:
                    - One or more VCI strings in quotes separated by spaces.
                type: list
                elements: dict
                suboptions:
                    vci_string:
                        description:
                            - VCI strings.
                        type: str
            wifi_ac1:
                description:
                    - WiFi Access Controller 1 IP address (DHCP option 138, RFC 5417).
                type: str
            wifi_ac2:
                description:
                    - WiFi Access Controller 2 IP address (DHCP option 138, RFC 5417).
                type: str
            wifi_ac3:
                description:
                    - WiFi Access Controller 3 IP address (DHCP option 138, RFC 5417).
                type: str
            wins_server1:
                description:
                    - WINS server 1.
                type: str
            wins_server2:
                description:
                    - WINS server 2.
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
  - name: Configure DHCP servers.
    fortiswitch_system_dhcp_server:
      state: "present"
      system_dhcp_server:
        auto_configuration: "disable"
        conflicted_ip_timeout: "4"
        default_gateway: "<your_own_value>"
        dns_server1: "<your_own_value>"
        dns_server2: "<your_own_value>"
        dns_server3: "<your_own_value>"
        dns_service: "local"
        domain: "<your_own_value>"
        exclude_range:
         -
            end_ip: "<your_own_value>"
            id:  "13"
            start_ip: "<your_own_value>"
        filename: "<your_own_value>"
        id:  "16"
        interface: "<your_own_value> (source system.interface.name)"
        ip_mode: "range"
        ip_range:
         -
            end_ip: "<your_own_value>"
            id:  "21"
            start_ip: "<your_own_value>"
        lease_time: "23"
        netmask: "<your_own_value>"
        next_server: "<your_own_value>"
        ntp_server1: "<your_own_value>"
        ntp_server2: "<your_own_value>"
        ntp_server3: "<your_own_value>"
        ntp_service: "local"
        options:
         -
            code: "31"
            id:  "32"
            ip: "<your_own_value>"
            type: "hex"
            value: "<your_own_value>"
        reserved_address:
         -
            action: "assign"
            circuit_id: "<your_own_value>"
            circuit_id_type: "hex"
            description: "<your_own_value>"
            id:  "41"
            ip: "<your_own_value>"
            mac: "<your_own_value>"
            remote_id: "<your_own_value>"
            remote_id_type: "hex"
            type: "mac"
        server_type: "regular"
        status: "disable"
        tftp_server:
         -
            tftp_server: "<your_own_value>"
        timezone: "01"
        timezone_option: "disable"
        vci_match: "disable"
        vci_string:
         -
            vci_string: "<your_own_value>"
        wifi_ac1: "<your_own_value>"
        wifi_ac2: "<your_own_value>"
        wifi_ac3: "<your_own_value>"
        wins_server1: "<your_own_value>"
        wins_server2: "<your_own_value>"

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
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.secret_field import is_secret_field


def filter_system_dhcp_server_data(json):
    option_list = ['auto_configuration', 'conflicted_ip_timeout', 'default_gateway',
                   'dns_server1', 'dns_server2', 'dns_server3',
                   'dns_service', 'domain', 'exclude_range',
                   'filename', 'id', 'interface',
                   'ip_mode', 'ip_range', 'lease_time',
                   'netmask', 'next_server', 'ntp_server1',
                   'ntp_server2', 'ntp_server3', 'ntp_service',
                   'options', 'reserved_address', 'server_type',
                   'status', 'tftp_server', 'timezone',
                   'timezone_option', 'vci_match', 'vci_string',
                   'wifi_ac1', 'wifi_ac2', 'wifi_ac3',
                   'wins_server1', 'wins_server2']
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


def system_dhcp_server(data, fos):

    state = data['state']

    system_dhcp_server_data = data['system_dhcp_server']
    filtered_data = underscore_to_hyphen(filter_system_dhcp_server_data(system_dhcp_server_data))

    if state == "present" or state is True:
        return fos.set('system.dhcp',
                       'server',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('system.dhcp',
                          'server',
                          mkey=filtered_data['id'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system_dhcp(data, fos):

    fos.do_member_operation('system_dhcp_server')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_dhcp_server']:
        resp = system_dhcp_server(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_dhcp_server'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp


versioned_schema = {
    "elements": "dict",
    "type": "list",
    "children": {
        "exclude_range": {
            "elements": "dict",
            "type": "list",
            "children": {
                "start_ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "end_ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "id": {
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
        },
        "domain": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "lease_time": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "ntp_server3": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "ntp_server2": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "ntp_server1": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "wifi_ac1": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "timezone_option": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "default",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "specify",
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
        "next_server": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "ip_range": {
            "elements": "dict",
            "type": "list",
            "children": {
                "start_ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "end_ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "id": {
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
        },
        "timezone": {
            "type": "string",
            "options": [
                {
                    "value": "01",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "02",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "03",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "04",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "05",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "81",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "06",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "07",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "08",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "09",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "10",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "11",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "12",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "13",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "74",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "14",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "77",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "15",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "87",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "16",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "17",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "18",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "19",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "20",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "75",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "21",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "22",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "23",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "24",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "80",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "79",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "25",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "26",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "27",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "28",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "78",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "29",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "30",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "31",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "32",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "33",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "34",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "35",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "36",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "37",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "38",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "83",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "84",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "40",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "85",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "41",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "42",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "43",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "39",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "44",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "46",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "47",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "51",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "48",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "45",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "49",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "50",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "52",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "53",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "54",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "55",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "56",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "57",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "58",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "59",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "60",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "62",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "63",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "61",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "64",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "65",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "66",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "67",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "68",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "69",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "70",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "71",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "72",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "00",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "82",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "73",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "86",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "76",
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
        "id": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "auto_configuration": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "enable",
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
        "conflicted_ip_timeout": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "dns_service": {
            "type": "string",
            "options": [
                {
                    "value": "local",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "default",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "specify",
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
        "default_gateway": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "ip_mode": {
            "type": "string",
            "options": [
                {
                    "value": "range",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "usrgrp",
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
        "filename": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "wifi_ac2": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "wifi_ac3": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "vci_match": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "enable",
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
        "ntp_service": {
            "type": "string",
            "options": [
                {
                    "value": "local",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "default",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "specify",
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
        "status": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "enable",
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
        "dns_server1": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "dns_server2": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "dns_server3": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "server_type": {
            "type": "string",
            "options": [
                {
                    "value": "regular",
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
        "tftp_server": {
            "elements": "dict",
            "type": "list",
            "children": {
                "tftp_server": {
                    "type": "string",
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
        },
        "netmask": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "reserved_address": {
            "elements": "dict",
            "type": "list",
            "children": {
                "description": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "circuit_id": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "remote_id": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "circuit_id_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "hex",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "string",
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
                "mac": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "assign",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "reserved",
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
                "type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "mac",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "option82",
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
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "remote_id_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "hex",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "string",
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
                }
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "interface": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "wins_server2": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "wins_server1": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True
            }
        },
        "vci_string": {
            "elements": "dict",
            "type": "list",
            "children": {
                "vci_string": {
                    "type": "string",
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
        },
        "options": {
            "elements": "dict",
            "type": "list",
            "children": {
                "ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "code": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "hex",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "string",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "ip",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "fqdn",
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
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True
                    }
                },
                "value": {
                    "type": "string",
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
    mkeyname = 'id'
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
        "system_dhcp_server": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_dhcp_server"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_dhcp_server"]['options'][attribute_name]['required'] = True
        if is_secret_field(attribute_name):
            fields["system_dhcp_server"]['options'][attribute_name]['no_log'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_dhcp_server")

        is_error, has_changed, result = fortiswitch_system_dhcp(module.params, fos)

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
