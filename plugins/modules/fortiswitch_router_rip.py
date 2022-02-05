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
module: fortiswitch_router_rip
short_description: RIP configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and rip category.
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
    
    router_rip:
        description:
            - RIP configuration.
        default: null
        type: dict
        suboptions:
            bfd:
                description:
                    - Bidirectional Forwarding Detection (BFD).
                type: str
                choices:
                    - enable
                    - disable
            default_information_originate:
                description:
                    - Generate a default route.
                type: str
                choices:
                    - enable
                    - disable
            default_metric:
                description:
                    - Default metric of redistribute routes (Except connected).
                type: int
            distance:
                description:
                    - Set admin distance based on route source ip.
                type: list
                suboptions:
                    access_list:
                        description:
                            - Access list for route destination. Source router.access-list.name.
                        type: str
                    distance:
                        description:
                            - Distance.
                        type: int
                    id:
                        description:
                            - Distance id.
                        required: true
                        type: int
                    prefix:
                        description:
                            - IP source prefix.
                        type: str
            distribute_list:
                description:
                    - Filter networks in routing updates.
                type: list
                suboptions:
                    direction:
                        description:
                            - Distribute list direction.
                        type: str
                        choices:
                            - in
                            - out
                    id:
                        description:
                            - Distribute-list id.
                        required: true
                        type: int
                    interface:
                        description:
                            - Distribute list interface name. Source system.interface.name.
                        type: str
                    listname:
                        description:
                            - Distribute access/prefix list name. Source router.access-list.name router.prefix-list.name.
                        type: str
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - enable
                            - disable
            garbage_timer:
                description:
                    - Garbage collection timer.
                type: int
            interface:
                description:
                    - RIP interface configuration
                type: list
                suboptions:
                    auth_keychain:
                        description:
                            - Authentication keychain name. Source router.key-chain.name.
                        type: str
                    auth_mode:
                        description:
                            - Authentication mode.
                        type: str
                        choices:
                            - none
                            - text
                            - md5
                    auth_string:
                        description:
                            - Authentication string/password.
                        type: str
                    flags:
                        description:
                            - flags
                        type: int
                    name:
                        description:
                            - interface name Source system.interface.name.
                        required: true
                        type: str
                    receive_version:
                        description:
                            - Receive version.
                        type: str
                        choices:
                            - global
                            - 1
                            - 2
                            - both
                    send_version:
                        description:
                            - Send version.
                        type: str
                        choices:
                            - global
                            - 1
                            - 2
                            - both
                    send_version2_broadcast:
                        description:
                            - broadcast version 1 compatible packets
                        type: str
                        choices:
                            - disable
                            - enable
                    split_horizon:
                        description:
                            - Split horizon method.
                        type: str
                        choices:
                            - poisoned
                            - regular
                    split_horizon_status:
                        description:
                            - Split horizon status.
                        type: str
                        choices:
                            - enable
                            - disable
            name:
                description:
                    - Vrf name.
                type: str
            neighbor:
                description:
                    - Specify a neighbor router. Required only for non-multicast networks.
                type: list
                suboptions:
                    id:
                        description:
                            - Neighbor entry id.
                        required: true
                        type: int
                    ip:
                        description:
                            - IP address.
                        type: str
            network:
                description:
                    - Enable RIP routing on an IP network.
                type: list
                suboptions:
                    id:
                        description:
                            - Network entry id.
                        required: true
                        type: int
                    prefix:
                        description:
                            - Network prefix.
                        type: str
            offset_list:
                description:
                    - Offset list to modify RIP metric.
                type: list
                suboptions:
                    access_list:
                        description:
                            - Access list name. Source router.access-list.name.
                        type: str
                    direction:
                        description:
                            - Offset list direction.
                        type: str
                        choices:
                            - in
                            - out
                    id:
                        description:
                            - Offset-list id.
                        required: true
                        type: int
                    interface:
                        description:
                            - Interface to match. Source system.interface.name.
                        type: str
                    offset:
                        description:
                            - Metric value.
                        type: int
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - enable
                            - disable
            passive_interface:
                description:
                    - Passive interface configuration.
                type: list
                suboptions:
                    name:
                        description:
                            - Passive interface name. Source system.interface.name.
                        required: true
                        type: str
            recv_buffer_size:
                description:
                    - receiving buffer size
                type: int
            redistribute:
                description:
                    - Redistribute configuration.
                type: list
                suboptions:
                    flags:
                        description:
                            - flags
                        type: int
                    metric:
                        description:
                            - Redistribute metric setting.
                        type: int
                    name:
                        description:
                            - Redistribute name.
                        required: true
                        type: str
                    routemap:
                        description:
                            - Route map name. Source router.route-map.name.
                        type: str
                    status:
                        description:
                            - status
                        type: str
                        choices:
                            - enable
                            - disable
            timeout_timer:
                description:
                    - Routing information timeout timer.
                type: int
            update_timer:
                description:
                    - Routing table update timer.
                type: int
            version:
                description:
                    - RIP version
                type: str
                choices:
                    - 1
                    - 2
            vrf:
                description:
                    - Enable RIP on VRF.
                type: list
                suboptions:
                    default_information_originate:
                        description:
                            - Generate a default route.
                        type: str
                        choices:
                            - enable
                            - disable
                    default_metric:
                        description:
                            - Default metric of redistribute routes (Except connected).
                        type: int
                    distance:
                        description:
                            - Set admin distance based on route source ip.
                        type: list
                        suboptions:
                            access_list:
                                description:
                                    - Access list for route destination. Source router.access-list.name.
                                type: str
                            distance:
                                description:
                                    - Distance.
                                type: int
                            id:
                                description:
                                    - Distance id.
                                required: true
                                type: int
                            prefix:
                                description:
                                    - IP source prefix.
                                type: str
                    distribute_list:
                        description:
                            - Filter networks in routing updates.
                        type: list
                        suboptions:
                            direction:
                                description:
                                    - Distribute list direction.
                                type: str
                                choices:
                                    - in
                                    - out
                            id:
                                description:
                                    - Distribute-list id.
                                required: true
                                type: int
                            interface:
                                description:
                                    - Distribute list interface name. Source system.interface.name.
                                type: str
                            listname:
                                description:
                                    - Distribute access/prefix list name. Source router.access-list.name router.prefix-list.name.
                                type: str
                            status:
                                description:
                                    - Status.
                                type: str
                                choices:
                                    - enable
                                    - disable
                    garbage_timer:
                        description:
                            - Garbage collection timer.
                        type: int
                    interface:
                        description:
                            - RIP interface configuration
                        type: list
                        suboptions:
                            auth_keychain:
                                description:
                                    - Authentication keychain name. Source router.key-chain.name.
                                type: str
                            auth_mode:
                                description:
                                    - Authentication mode.
                                type: str
                                choices:
                                    - none
                                    - text
                                    - md5
                            auth_string:
                                description:
                                    - Authentication string/password.
                                type: str
                            flags:
                                description:
                                    - flags
                                type: int
                            name:
                                description:
                                    - interface name Source system.interface.name.
                                required: true
                                type: str
                            receive_version:
                                description:
                                    - Receive version.
                                type: str
                                choices:
                                    - global
                                    - 1
                                    - 2
                                    - both
                            send_version:
                                description:
                                    - Send version.
                                type: str
                                choices:
                                    - global
                                    - 1
                                    - 2
                                    - both
                            send_version2_broadcast:
                                description:
                                    - broadcast version 1 compatible packets
                                type: str
                                choices:
                                    - disable
                                    - enable
                            split_horizon:
                                description:
                                    - Split horizon method.
                                type: str
                                choices:
                                    - poisoned
                                    - regular
                            split_horizon_status:
                                description:
                                    - Split horizon status.
                                type: str
                                choices:
                                    - enable
                                    - disable
                    name:
                        description:
                            - Vrf name. Source router.vrf.name.
                        required: true
                        type: str
                    neighbor:
                        description:
                            - Specify a neighbor router. Required only for non-multicast networks.
                        type: list
                        suboptions:
                            id:
                                description:
                                    - Neighbor entry id.
                                required: true
                                type: int
                            ip:
                                description:
                                    - IP address.
                                type: str
                    network:
                        description:
                            - Enable RIP routing on an IP network.
                        type: list
                        suboptions:
                            id:
                                description:
                                    - Network entry id.
                                required: true
                                type: int
                            prefix:
                                description:
                                    - Network prefix.
                                type: str
                    offset_list:
                        description:
                            - Offset list to modify RIP metric.
                        type: list
                        suboptions:
                            access_list:
                                description:
                                    - Access list name. Source router.access-list.name.
                                type: str
                            direction:
                                description:
                                    - Offset list direction.
                                type: str
                                choices:
                                    - in
                                    - out
                            id:
                                description:
                                    - Offset-list id.
                                required: true
                                type: int
                            interface:
                                description:
                                    - Interface to match. Source system.interface.name.
                                type: str
                            offset:
                                description:
                                    - Metric value.
                                type: int
                            status:
                                description:
                                    - Status.
                                type: str
                                choices:
                                    - enable
                                    - disable
                    passive_interface:
                        description:
                            - Passive interface configuration.
                        type: list
                        suboptions:
                            name:
                                description:
                                    - Passive interface name. Source system.interface.name.
                                required: true
                                type: str
                    recv_buffer_size:
                        description:
                            - receiving buffer size
                        type: int
                    redistribute:
                        description:
                            - Redistribute configuration.
                        type: list
                        suboptions:
                            flags:
                                description:
                                    - flags
                                type: int
                            metric:
                                description:
                                    - Redistribute metric setting.
                                type: int
                            name:
                                description:
                                    - Redistribute name.
                                required: true
                                type: str
                            routemap:
                                description:
                                    - Route map name. Source router.route-map.name.
                                type: str
                            status:
                                description:
                                    - status
                                type: str
                                choices:
                                    - enable
                                    - disable
                    timeout_timer:
                        description:
                            - Routing information timeout timer.
                        type: int
                    update_timer:
                        description:
                            - Routing table update timer.
                        type: int
                    version:
                        description:
                            - RIP version
                        type: str
                        choices:
                            - 1
                            - 2
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
  - name: RIP configuration.
    fortiswitch_router_rip:
      state: "present"
      router_rip:
        bfd: "enable"
        default_information_originate: "enable"
        default_metric: "5"
        distance:
         -
            access_list: "<your_own_value> (source router.access-list.name)"
            distance: "8"
            id:  "9"
            prefix: "<your_own_value>"
        distribute_list:
         -
            direction: "in"
            id:  "13"
            interface: "<your_own_value> (source system.interface.name)"
            listname: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
            status: "enable"
        garbage_timer: "17"
        interface:
         -
            auth_keychain: "<your_own_value> (source router.key-chain.name)"
            auth_mode: "none"
            auth_string: "<your_own_value>"
            flags: "22"
            name: "default_name_23 (source system.interface.name)"
            receive_version: "global"
            send_version: "global"
            send_version2_broadcast: "disable"
            split_horizon: "poisoned"
            split_horizon_status: "enable"
        name: "default_name_29"
        neighbor:
         -
            id:  "31"
            ip: "<your_own_value>"
        network:
         -
            id:  "34"
            prefix: "<your_own_value>"
        offset_list:
         -
            access_list: "<your_own_value> (source router.access-list.name)"
            direction: "in"
            id:  "39"
            interface: "<your_own_value> (source system.interface.name)"
            offset: "41"
            status: "enable"
        passive_interface:
         -
            name: "default_name_44 (source system.interface.name)"
        recv_buffer_size: "45"
        redistribute:
         -
            flags: "47"
            metric: "48"
            name: "default_name_49"
            routemap: "<your_own_value> (source router.route-map.name)"
            status: "enable"
        timeout_timer: "52"
        update_timer: "53"
        version: "1"
        vrf:
         -
            default_information_originate: "enable"
            default_metric: "57"
            distance:
             -
                access_list: "<your_own_value> (source router.access-list.name)"
                distance: "60"
                id:  "61"
                prefix: "<your_own_value>"
            distribute_list:
             -
                direction: "in"
                id:  "65"
                interface: "<your_own_value> (source system.interface.name)"
                listname: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
                status: "enable"
            garbage_timer: "69"
            interface:
             -
                auth_keychain: "<your_own_value> (source router.key-chain.name)"
                auth_mode: "none"
                auth_string: "<your_own_value>"
                flags: "74"
                name: "default_name_75 (source system.interface.name)"
                receive_version: "global"
                send_version: "global"
                send_version2_broadcast: "disable"
                split_horizon: "poisoned"
                split_horizon_status: "enable"
            name: "default_name_81 (source router.vrf.name)"
            neighbor:
             -
                id:  "83"
                ip: "<your_own_value>"
            network:
             -
                id:  "86"
                prefix: "<your_own_value>"
            offset_list:
             -
                access_list: "<your_own_value> (source router.access-list.name)"
                direction: "in"
                id:  "91"
                interface: "<your_own_value> (source system.interface.name)"
                offset: "93"
                status: "enable"
            passive_interface:
             -
                name: "default_name_96 (source system.interface.name)"
            recv_buffer_size: "97"
            redistribute:
             -
                flags: "99"
                metric: "100"
                name: "default_name_101"
                routemap: "<your_own_value> (source router.route-map.name)"
                status: "enable"
            timeout_timer: "104"
            update_timer: "105"
            version: "1"

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
def filter_router_rip_data(json):
    option_list = ['bfd', 'default_information_originate', 'default_metric',
                   'distance', 'distribute_list', 'garbage_timer',
                   'interface', 'name', 'neighbor',
                   'network', 'offset_list', 'passive_interface',
                   'recv_buffer_size', 'redistribute', 'timeout_timer',
                   'update_timer', 'version', 'vrf' ]
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

def router_rip(data, fos):
    router_rip_data = data['router_rip']
    filtered_data = underscore_to_hyphen(filter_router_rip_data(router_rip_data))

    
    return fos.set('router',
                    'rip',
                    data=filtered_data,
                    )
    

def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404




def fortiswitch_router(data, fos):

    fos.do_member_operation('router_rip')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['router_rip']:
        resp = router_rip(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('router_rip'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp



versioned_schema = {
    "type": "dict", 
    "children": {
        "distance": {
            "type": "list", 
            "children": {
                "distance": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "prefix": {
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
                }, 
                "access_list": {
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
        "redistribute": {
            "type": "list", 
            "children": {
                "status": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "enable", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "disable", 
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
                "metric": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "routemap": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "flags": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "name": {
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
        "distribute_list": {
            "type": "list", 
            "children": {
                "status": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "enable", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "disable", 
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
                "listname": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "direction": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "in", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "out", 
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
                "interface": {
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
        "name": {
            "type": "string", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "bfd": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "default_metric": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "garbage_timer": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "update_timer": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "neighbor": {
            "type": "list", 
            "children": {
                "ip": {
                    "type": "string", 
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
                "v7.0.3": False, 
                "v7.0.2": False, 
                "v7.0.1": False, 
                "v7.0.0": True
            }
        }, 
        "default_information_originate": {
            "type": "string", 
            "options": [
                {
                    "value": "enable", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "disable", 
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
        "version": {
            "type": "string", 
            "options": [
                {
                    "value": "1", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                {
                    "value": "2", 
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
        "vrf": {
            "type": "list", 
            "children": {
                "distance": {
                    "type": "list", 
                    "children": {
                        "distance": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "prefix": {
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
                        }, 
                        "access_list": {
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
                "redistribute": {
                    "type": "list", 
                    "children": {
                        "status": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "enable", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "disable", 
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
                        "metric": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "routemap": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "flags": {
                            "type": "integer", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "name": {
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
                "distribute_list": {
                    "type": "list", 
                    "children": {
                        "status": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "enable", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "disable", 
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
                        "listname": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "direction": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "in", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "out", 
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
                        "interface": {
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
                "name": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "default_metric": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "garbage_timer": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "update_timer": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "neighbor": {
                    "type": "list", 
                    "children": {
                        "ip": {
                            "type": "string", 
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
                        "v7.0.3": False, 
                        "v7.0.2": False, 
                        "v7.0.1": False, 
                        "v7.0.0": True
                    }
                }, 
                "default_information_originate": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "enable", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "disable", 
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
                "version": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "1", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "2", 
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
                "passive_interface": {
                    "type": "list", 
                    "children": {
                        "name": {
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
                "recv_buffer_size": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "interface": {
                    "type": "list", 
                    "children": {
                        "auth_keychain": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "receive_version": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "global", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "1", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "2", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "both", 
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
                        "name": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "split_horizon_status": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "enable", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "disable", 
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
                        "auth_mode": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "none", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "text", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "md5", 
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
                        "split_horizon": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "poisoned", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
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
                        "send_version": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "global", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "1", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "2", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "both", 
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
                        "send_version2_broadcast": {
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
                        "auth_string": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "flags": {
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
                "timeout_timer": {
                    "type": "integer", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "network": {
                    "type": "list", 
                    "children": {
                        "prefix": {
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
                "offset_list": {
                    "type": "list", 
                    "children": {
                        "status": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "enable", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "disable", 
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
                        "direction": {
                            "type": "string", 
                            "options": [
                                {
                                    "value": "in", 
                                    "revisions": {
                                        "v7.0.3": True, 
                                        "v7.0.2": True, 
                                        "v7.0.1": True, 
                                        "v7.0.0": True
                                    }
                                }, 
                                {
                                    "value": "out", 
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
                        "access_list": {
                            "type": "string", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        "offset": {
                            "type": "integer", 
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
                }
            }, 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "passive_interface": {
            "type": "list", 
            "children": {
                "name": {
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
        "recv_buffer_size": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "interface": {
            "type": "list", 
            "children": {
                "auth_keychain": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "receive_version": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "global", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "1", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "2", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "both", 
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
                "name": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "split_horizon_status": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "enable", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "disable", 
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
                "auth_mode": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "none", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "text", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "md5", 
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
                "split_horizon": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "poisoned", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
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
                "send_version": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "global", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "1", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "2", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "both", 
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
                "send_version2_broadcast": {
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
                "auth_string": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "flags": {
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
        "timeout_timer": {
            "type": "integer", 
            "revisions": {
                "v7.0.3": True, 
                "v7.0.2": True, 
                "v7.0.1": True, 
                "v7.0.0": True
            }
        }, 
        "network": {
            "type": "list", 
            "children": {
                "prefix": {
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
        "offset_list": {
            "type": "list", 
            "children": {
                "status": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "enable", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "disable", 
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
                "direction": {
                    "type": "string", 
                    "options": [
                        {
                            "value": "in", 
                            "revisions": {
                                "v7.0.3": True, 
                                "v7.0.2": True, 
                                "v7.0.1": True, 
                                "v7.0.0": True
                            }
                        }, 
                        {
                            "value": "out", 
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
                "access_list": {
                    "type": "string", 
                    "revisions": {
                        "v7.0.3": True, 
                        "v7.0.2": True, 
                        "v7.0.1": True, 
                        "v7.0.0": True
                    }
                }, 
                "offset": {
                    "type": "integer", 
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
    mkeyname = None
    fields = {
        "enable_log": {"required": False, "type": bool},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "router_rip": {
            "required": False, "type": "dict", "default": None,
            "options": { 
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["router_rip"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["router_rip"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "router_rip")
        
        is_error, has_changed, result = fortiswitch_router(module.params, fos)
        
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