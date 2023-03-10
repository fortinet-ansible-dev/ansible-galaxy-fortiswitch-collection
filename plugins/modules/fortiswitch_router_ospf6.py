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
module: fortiswitch_router_ospf6
short_description: Router OSPF6 configuration in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify router feature and ospf6 category.
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

    router_ospf6:
        description:
            - Router OSPF6 configuration.
        default: null
        type: dict
        suboptions:
            area:
                description:
                    - OSPF6 area configuration.
                type: list
                elements: dict
                suboptions:
                    filter_list:
                        description:
                            - OSPF area filter-list configuration.
                        type: list
                        elements: dict
                        suboptions:
                            direction:
                                description:
                                    - Direction.
                                type: str
                                choices:
                                    - 'in'
                                    - 'out'
                            id:
                                description:
                                    - Filter list entry ID.
                                type: int
                            list:
                                description:
                                    - Access-list or prefix-list name. Source router.access-list6.name router.prefix-list6.name.
                                type: str
                    id:
                        description:
                            - Area entry ip address.
                        type: str
                    range:
                        description:
                            - OSPF6 area range configuration.
                        type: list
                        elements: dict
                        suboptions:
                            advertise:
                                description:
                                    - Enable/disable advertise status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            id:
                                description:
                                    - Range entry id.
                                type: int
                            prefix6:
                                description:
                                    - <prefix6>   IPv6 prefix
                                type: str
                    stub_type:
                        description:
                            - Stub summary setting.
                        type: str
                        choices:
                            - 'no-summary'
                            - 'summary'
                    type:
                        description:
                            - Area type setting.
                        type: str
                        choices:
                            - 'regular'
                            - 'stub'
            interface:
                description:
                    - OSPF6 interface configuration.
                type: list
                elements: dict
                suboptions:
                    area_id:
                        description:
                            - A.B.C.D, in IPv4 address format.
                        type: str
                    bfd:
                        description:
                            - Enable/Disable Bidirectional Forwarding Detection (BFD).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cost:
                        description:
                            - The cost of the interface.
                        type: int
                    dead_interval:
                        description:
                            - Dead interval.
                        type: int
                    hello_interval:
                        description:
                            - Hello interval.
                        type: int
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        type: str
                    passive:
                        description:
                            - Enable/disable passive interface.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    priority:
                        description:
                            - Router priority.
                        type: int
                    retransmit_interval:
                        description:
                            - Time between retransmitting lost link state advertisements.
                        type: int
                    status:
                        description:
                            - Enable/disable OSPF6 routing on this interface.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    transmit_delay:
                        description:
                            - Link state transmit delay.
                        type: int
            log_neighbor_changes:
                description:
                    - Enable logging of OSPF neighbor"s changes.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redistribute:
                description:
                    - Redistribute configuration.
                type: list
                elements: dict
                suboptions:
                    metric:
                        description:
                            - Redistribute metric setting.
                        type: int
                    metric_type:
                        description:
                            - metric type
                        type: str
                        choices:
                            - '1'
                            - '2'
                    name:
                        description:
                            - Redistribute name.
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
                            - 'enable'
                            - 'disable'
            router_id:
                description:
                    - A.B.C.D, in IPv4 address format.
                type: str
            spf_timers:
                description:
                    - SPF calculation frequency.
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
  - name: Router OSPF6 configuration.
    fortiswitch_router_ospf6:
      router_ospf6:
        area:
         -
            filter_list:
             -
                direction: "in"
                id:  "6"
                list: "<your_own_value> (source router.access-list6.name router.prefix-list6.name)"
            id:  "8"
            range:
             -
                advertise: "disable"
                id:  "11"
                prefix6: "<your_own_value>"
            stub_type: "no-summary"
            type: "regular"
        interface:
         -
            area_id: "<your_own_value>"
            bfd: "enable"
            cost: "18"
            dead_interval: "19"
            hello_interval: "20"
            name: "default_name_21 (source system.interface.name)"
            passive: "enable"
            priority: "23"
            retransmit_interval: "24"
            status: "disable"
            transmit_delay: "26"
        log_neighbor_changes: "enable"
        redistribute:
         -
            metric: "29"
            metric_type: "1"
            name: "default_name_31"
            routemap: "<your_own_value> (source router.route-map.name)"
            status: "enable"
        router_id: "<your_own_value>"
        spf_timers: "<your_own_value>"

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


def filter_router_ospf6_data(json):
    option_list = ['area', 'interface', 'log_neighbor_changes',
                   'redistribute', 'router_id', 'spf_timers']

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


def router_ospf6(data, fos):
    router_ospf6_data = data['router_ospf6']
    filtered_data = underscore_to_hyphen(filter_router_ospf6_data(router_ospf6_data))

    return fos.set('router',
                   'ospf6',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_router(data, fos):
    fos.do_member_operation('router', 'ospf6')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['router_ospf6']:
        resp = router_ospf6(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('router_ospf6'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "type": "dict",
    "children": {
        "router_id": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "redistribute": {
            "elements": "dict",
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
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "metric_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "1",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        {
                            "value": "2",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "metric": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "routemap": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "name": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                }
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "area": {
            "elements": "dict",
            "type": "list",
            "children": {
                "stub_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "no-summary",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        {
                            "value": "summary",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "regular",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        {
                            "value": "stub",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "range": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "advertise": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                        "v7.0.1": True,
                                        "v7.0.0": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True
                                    }
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                        "v7.0.1": True,
                                        "v7.0.0": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        "id": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        "prefix6": {
                            "type": "string",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "filter_list": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "direction": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "in",
                                    "revisions": {
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                        "v7.0.1": True,
                                        "v7.0.0": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True
                                    }
                                },
                                {
                                    "value": "out",
                                    "revisions": {
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                        "v7.0.1": True,
                                        "v7.0.0": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        "list": {
                            "type": "string",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        "id": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "id": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                }
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "spf_timers": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "interface": {
            "elements": "dict",
            "type": "list",
            "children": {
                "status": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "priority": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "area_id": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "cost": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "name": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
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
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "retransmit_interval": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "passive": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "dead_interval": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "hello_interval": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                "transmit_delay": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                }
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        },
        "log_neighbor_changes": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True
                    }
                }
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True
            }
        }
    },
    "revisions": {
        "v7.0.3": True,
        "v7.0.2": True,
        "v7.0.1": True,
        "v7.0.0": True,
        "v7.0.6": True,
        "v7.0.5": True,
        "v7.0.4": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
    fields = {
        "enable_log": {"required": False, "type": "bool", "default": False},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"]
        },
        "router_ospf6": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["router_ospf6"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["router_ospf6"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "router_ospf6")
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
