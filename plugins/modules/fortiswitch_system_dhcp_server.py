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
                    - 'disable'
                    - 'enable'
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
                    - 'local'
                    - 'default'
                    - 'specify'
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
                    - DHCP server can assign IP configurations to clients connected to this interface.
                type: str
            ip_mode:
                description:
                    - Method used to assign client IP.
                type: str
                choices:
                    - 'range'
                    - 'usrgrp'
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
                    - 'local'
                    - 'default'
                    - 'specify'
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
                            - 'hex'
                            - 'string'
                            - 'ip'
                            - 'fqdn'
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
                            - 'assign'
                            - 'block'
                            - 'reserved'
                    circuit_id:
                        description:
                            - Option 82 circuit-ID of the client that will get the reserved IP address.
                        type: str
                    circuit_id_type:
                        description:
                            - DHCP option type.
                        type: str
                        choices:
                            - 'hex'
                            - 'string'
                    description:
                        description:
                            - Description.
                        type: str
                    id:
                        description:
                            - ID.
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
                            - 'hex'
                            - 'string'
                    type:
                        description:
                            - DHCP reserved-address type.
                        type: str
                        choices:
                            - 'mac'
                            - 'option82'
            server_type:
                description:
                    - DHCP server can be a normal DHCP server or an IPsec DHCP server.
                type: str
                choices:
                    - 'regular'
            status:
                description:
                    - Enable/disable this DHCP configuration.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
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
                    - '01'
                    - '02'
                    - '03'
                    - '04'
                    - '05'
                    - '81'
                    - '06'
                    - '07'
                    - '08'
                    - '09'
                    - '10'
                    - '11'
                    - '12'
                    - '13'
                    - '74'
                    - '14'
                    - '77'
                    - '15'
                    - '87'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '75'
                    - '21'
                    - '22'
                    - '23'
                    - '24'
                    - '80'
                    - '79'
                    - '25'
                    - '26'
                    - '27'
                    - '28'
                    - '78'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
                    - '33'
                    - '34'
                    - '35'
                    - '36'
                    - '37'
                    - '38'
                    - '83'
                    - '84'
                    - '40'
                    - '85'
                    - '41'
                    - '42'
                    - '43'
                    - '39'
                    - '44'
                    - '46'
                    - '47'
                    - '51'
                    - '48'
                    - '45'
                    - '49'
                    - '50'
                    - '52'
                    - '53'
                    - '54'
                    - '55'
                    - '56'
                    - '57'
                    - '58'
                    - '59'
                    - '60'
                    - '62'
                    - '63'
                    - '61'
                    - '64'
                    - '65'
                    - '66'
                    - '67'
                    - '68'
                    - '69'
                    - '70'
                    - '71'
                    - '72'
                    - '00'
                    - '82'
                    - '73'
                    - '86'
                    - '76'
                    - '88'
                    - '89'
                    - '90'
                    - '91'
                    - '92'
            timezone_option:
                description:
                    - Options for the DHCP server to set the client"s time zone.
                type: str
                choices:
                    - 'disable'
                    - 'default'
                    - 'specify'
            vci_match:
                description:
                    - Enable/disable vendor class identifier (VCI) matching. When enabled only DHCP requests with a matching VCI are served.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
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
- name: Configure DHCP servers.
  fortinet.fortiswitch.fortiswitch_system_dhcp_server:
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
                  id: "13"
                  start_ip: "<your_own_value>"
          filename: "<your_own_value>"
          id: "16"
          interface: "<your_own_value> (source system.interface.name)"
          ip_mode: "range"
          ip_range:
              -
                  end_ip: "<your_own_value>"
                  id: "21"
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
                  id: "32"
                  ip: "<your_own_value>"
                  type: "hex"
                  value: "<your_own_value>"
          reserved_address:
              -
                  action: "assign"
                  circuit_id: "<your_own_value>"
                  circuit_id_type: "hex"
                  description: "<your_own_value>"
                  id: "41"
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
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.data_post_processor import remove_invalid_fields
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import is_same_comparison
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import serialize


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


def system_dhcp_server(data, fos, check_mode=False):
    state = data['state']
    system_dhcp_server_data = data['system_dhcp_server']
    filtered_data = underscore_to_hyphen(filter_system_dhcp_server_data(system_dhcp_server_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": '',
            "after": filtered_data,
        }
        mkey = fos.get_mkey('system.dhcp', 'server', filtered_data)
        current_data = fos.get('system.dhcp', 'server', mkey=mkey)
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


def fortiswitch_system_dhcp(data, fos, check_mode):
    fos.do_member_operation('system.dhcp', 'server')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_dhcp_server']:
        resp = system_dhcp_server(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_dhcp_server'))
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
        "domain": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "domain",
            "help": "Domain name suffix for the IP addresses that the DHCP server assigns to clients.",
            "category": "unitary"
        },
        "lease_time": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "lease-time",
            "help": "Lease time in seconds,0 means unlimited.",
            "category": "unitary"
        },
        "exclude_range": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "id",
                    "help": "ID.",
                    "category": "unitary"
                },
                "start_ip": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "start-ip",
                    "help": "Start of IP range.",
                    "category": "unitary"
                },
                "end_ip": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "end-ip",
                    "help": "End of IP range.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "exclude-range",
            "help": "Exclude one or more ranges of IP addresses from being assigned to clients.",
            "mkey": "id",
            "category": "table"
        },
        "server_type": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "regular"
                }
            ],
            "name": "server-type",
            "help": "DHCP server can be a normal DHCP server or an IPsec DHCP server.",
            "category": "unitary"
        },
        "conflicted_ip_timeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "conflicted-ip-timeout",
            "help": "Time in seconds to wait after a conflicted IP address is removed from the DHCP range before it can be reused.",
            "category": "unitary"
        },
        "timezone_option": {
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
                    "value": "default"
                },
                {
                    "value": "specify"
                }
            ],
            "name": "timezone-option",
            "help": "Options for the DHCP server to set the client's time zone.",
            "category": "unitary"
        },
        "timezone": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "01"
                },
                {
                    "value": "02"
                },
                {
                    "value": "03"
                },
                {
                    "value": "04"
                },
                {
                    "value": "05"
                },
                {
                    "value": "81"
                },
                {
                    "value": "06"
                },
                {
                    "value": "07"
                },
                {
                    "value": "08"
                },
                {
                    "value": "09"
                },
                {
                    "value": "10"
                },
                {
                    "value": "11"
                },
                {
                    "value": "12"
                },
                {
                    "value": "13"
                },
                {
                    "value": "74"
                },
                {
                    "value": "14"
                },
                {
                    "value": "77"
                },
                {
                    "value": "15"
                },
                {
                    "value": "87"
                },
                {
                    "value": "16"
                },
                {
                    "value": "17"
                },
                {
                    "value": "18"
                },
                {
                    "value": "19"
                },
                {
                    "value": "20"
                },
                {
                    "value": "75"
                },
                {
                    "value": "21"
                },
                {
                    "value": "22"
                },
                {
                    "value": "23"
                },
                {
                    "value": "24"
                },
                {
                    "value": "80"
                },
                {
                    "value": "79"
                },
                {
                    "value": "25"
                },
                {
                    "value": "26"
                },
                {
                    "value": "27"
                },
                {
                    "value": "28"
                },
                {
                    "value": "78"
                },
                {
                    "value": "29"
                },
                {
                    "value": "30"
                },
                {
                    "value": "31"
                },
                {
                    "value": "32"
                },
                {
                    "value": "33"
                },
                {
                    "value": "34"
                },
                {
                    "value": "35"
                },
                {
                    "value": "36"
                },
                {
                    "value": "37"
                },
                {
                    "value": "38"
                },
                {
                    "value": "83"
                },
                {
                    "value": "84"
                },
                {
                    "value": "40"
                },
                {
                    "value": "85"
                },
                {
                    "value": "41"
                },
                {
                    "value": "42"
                },
                {
                    "value": "43"
                },
                {
                    "value": "39"
                },
                {
                    "value": "44"
                },
                {
                    "value": "46"
                },
                {
                    "value": "47"
                },
                {
                    "value": "51"
                },
                {
                    "value": "48"
                },
                {
                    "value": "45"
                },
                {
                    "value": "49"
                },
                {
                    "value": "50"
                },
                {
                    "value": "52"
                },
                {
                    "value": "53"
                },
                {
                    "value": "54"
                },
                {
                    "value": "55"
                },
                {
                    "value": "56"
                },
                {
                    "value": "57"
                },
                {
                    "value": "58"
                },
                {
                    "value": "59"
                },
                {
                    "value": "60"
                },
                {
                    "value": "62"
                },
                {
                    "value": "63"
                },
                {
                    "value": "61"
                },
                {
                    "value": "64"
                },
                {
                    "value": "65"
                },
                {
                    "value": "66"
                },
                {
                    "value": "67"
                },
                {
                    "value": "68"
                },
                {
                    "value": "69"
                },
                {
                    "value": "70"
                },
                {
                    "value": "71"
                },
                {
                    "value": "72"
                },
                {
                    "value": "00"
                },
                {
                    "value": "82"
                },
                {
                    "value": "73"
                },
                {
                    "value": "86"
                },
                {
                    "value": "76"
                },
                {
                    "value": "88",
                    "v_range": [
                        [
                            "v7.4.2",
                            ""
                        ]
                    ]
                },
                {
                    "value": "89",
                    "v_range": [
                        [
                            "v7.4.2",
                            ""
                        ]
                    ]
                },
                {
                    "value": "90",
                    "v_range": [
                        [
                            "v7.4.2",
                            ""
                        ]
                    ]
                },
                {
                    "value": "91",
                    "v_range": [
                        [
                            "v7.4.2",
                            ""
                        ]
                    ]
                },
                {
                    "value": "92",
                    "v_range": [
                        [
                            "v7.4.2",
                            ""
                        ]
                    ]
                }
            ],
            "name": "timezone",
            "help": "Select the time zone to be assigned to DHCP clients.",
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
            "help": "ID.",
            "category": "unitary"
        },
        "filename": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "filename",
            "help": "Name of the boot file on the TFTP server.",
            "category": "unitary"
        },
        "ntp_server1": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "ntp-server1",
            "help": "NTP server 1.",
            "category": "unitary"
        },
        "default_gateway": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "default-gateway",
            "help": "Default gateway IP address assigned by the DHCP server.",
            "category": "unitary"
        },
        "next_server": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "next-server",
            "help": "IP address of a server (for example,a TFTP sever) that DHCP clients can download a boot file from.",
            "category": "unitary"
        },
        "ntp_server2": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "ntp-server2",
            "help": "NTP server 2.",
            "category": "unitary"
        },
        "dns_service": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "local"
                },
                {
                    "value": "default"
                },
                {
                    "value": "specify"
                }
            ],
            "name": "dns-service",
            "help": "Options for assigning DNS servers to DHCP clients.",
            "category": "unitary"
        },
        "ip_range": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "id",
                    "help": "ID.",
                    "category": "unitary"
                },
                "start_ip": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "start-ip",
                    "help": "Start of IP range.",
                    "category": "unitary"
                },
                "end_ip": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "end-ip",
                    "help": "End of IP range.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "ip-range",
            "help": "DHCP IP range configuration.",
            "mkey": "id",
            "category": "table"
        },
        "ip_mode": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "range"
                },
                {
                    "value": "usrgrp"
                }
            ],
            "name": "ip-mode",
            "help": "Method used to assign client IP.",
            "category": "unitary"
        },
        "auto_configuration": {
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
            "name": "auto-configuration",
            "help": "Enable/disable auto configuration.",
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
                    "value": "disable"
                },
                {
                    "value": "enable"
                }
            ],
            "name": "status",
            "help": "Enable/disable this DHCP configuration.",
            "category": "unitary"
        },
        "reserved_address": {
            "type": "list",
            "elements": "dict",
            "children": {
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
                "ip": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "ip",
                    "help": "IP address to be reserved for the MAC address.",
                    "category": "unitary"
                },
                "mac": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "mac",
                    "help": "MAC address of the client that will get the reserved IP address.",
                    "category": "unitary"
                },
                "circuit_id_type": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "hex"
                        },
                        {
                            "value": "string"
                        }
                    ],
                    "name": "circuit-id-type",
                    "help": "DHCP option type.",
                    "category": "unitary"
                },
                "circuit_id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "circuit-id",
                    "help": "Option 82 circuit-ID of the client that will get the reserved IP address.",
                    "category": "unitary"
                },
                "action": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "assign"
                        },
                        {
                            "value": "block"
                        },
                        {
                            "value": "reserved"
                        }
                    ],
                    "name": "action",
                    "help": "Options for the DHCP server to configure the client with the reserved MAC address.",
                    "category": "unitary"
                },
                "remote_id": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "remote-id",
                    "help": "Option 82 remote-ID of the client that will get the reserved IP address.",
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
                            "value": "mac"
                        },
                        {
                            "value": "option82"
                        }
                    ],
                    "name": "type",
                    "help": "DHCP reserved-address type.",
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
                    "help": "ID.",
                    "category": "unitary"
                },
                "remote_id_type": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "options": [
                        {
                            "value": "hex"
                        },
                        {
                            "value": "string"
                        }
                    ],
                    "name": "remote-id-type",
                    "help": "DHCP option type.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "reserved-address",
            "help": "Options for the DHCP server to assign IP settings to specific MAC addresses.",
            "mkey": "id",
            "category": "table"
        },
        "ntp_server3": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "ntp-server3",
            "help": "NTP server 3.",
            "category": "unitary"
        },
        "netmask": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "netmask",
            "help": "Netmask assigned by the DHCP server.",
            "category": "unitary"
        },
        "ntp_service": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "local"
                },
                {
                    "value": "default"
                },
                {
                    "value": "specify"
                }
            ],
            "name": "ntp-service",
            "help": "Options for assigning Network Time Protocol (NTP) servers to DHCP clients.",
            "category": "unitary"
        },
        "wins_server1": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "wins-server1",
            "help": "WINS server 1.",
            "category": "unitary"
        },
        "wins_server2": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "wins-server2",
            "help": "WINS server 2.",
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
            "help": "DHCP server can assign IP configurations to clients connected to this interface.",
            "category": "unitary"
        },
        "wifi_ac1": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "wifi-ac1",
            "help": "WiFi Access Controller 1 IP address (DHCP option 138,RFC 5417).",
            "category": "unitary"
        },
        "wifi_ac2": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "wifi-ac2",
            "help": "WiFi Access Controller 2 IP address (DHCP option 138,RFC 5417).",
            "category": "unitary"
        },
        "wifi_ac3": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "wifi-ac3",
            "help": "WiFi Access Controller 3 IP address (DHCP option 138,RFC 5417).",
            "category": "unitary"
        },
        "options": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "ip",
                    "help": "DHCP option IPs.",
                    "category": "unitary"
                },
                "code": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "integer",
                    "name": "code",
                    "help": "DHCP option code.",
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
                            "value": "hex"
                        },
                        {
                            "value": "string"
                        },
                        {
                            "value": "ip"
                        },
                        {
                            "value": "fqdn"
                        }
                    ],
                    "name": "type",
                    "help": "DHCP option type.",
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
                    "help": "ID.",
                    "category": "unitary"
                },
                "value": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "value",
                    "help": "DHCP option value.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "options",
            "help": "DHCP options.",
            "mkey": "id",
            "category": "table"
        },
        "vci_string": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vci_string": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "vci-string",
                    "help": "VCI strings.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "vci-string",
            "help": "One or more VCI strings in quotes separated by spaces.",
            "mkey": "vci-string",
            "category": "table"
        },
        "dns_server2": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "dns-server2",
            "help": "DNS server 2.",
            "category": "unitary"
        },
        "dns_server3": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "dns-server3",
            "help": "DNS server 3.",
            "category": "unitary"
        },
        "dns_server1": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "dns-server1",
            "help": "DNS server 1.",
            "category": "unitary"
        },
        "tftp_server": {
            "type": "list",
            "elements": "dict",
            "children": {
                "tftp_server": {
                    "v_range": [
                        [
                            "v7.0.0",
                            ""
                        ]
                    ],
                    "type": "string",
                    "name": "tftp-server",
                    "help": "TFTP server.",
                    "category": "unitary"
                }
            },
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "name": "tftp-server",
            "help": "One or more hostnames or IP addresses of the TFTP servers in quotes separated by spaces.",
            "mkey": "tftp-server",
            "category": "table"
        },
        "vci_match": {
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
            "name": "vci-match",
            "help": "Enable/disable vendor class identifier (VCI) matching. When enabled only DHCP requests with a matching VCI are served.",
            "category": "unitary"
        }
    },
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "name": "server",
    "help": "Configure DHCP servers.",
    "mkey": "id",
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
        "system_dhcp_server": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_dhcp_server"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_dhcp_server"]['options'][attribute_name]['required'] = True

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
            connection.set_custom_option('enable_log', module.params['enable_log'])
        else:
            connection.set_custom_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_dhcp_server")
        is_error, has_changed, result, diff = fortiswitch_system_dhcp(module.params, fos, module.check_mode)
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
