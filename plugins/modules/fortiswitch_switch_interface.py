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
module: fortiswitch_switch_interface
short_description: Usable interfaces (trunks and ports) in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch feature and interface category.
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
    switch_interface:
        description:
            - Usable interfaces (trunks and ports).
        default: null
        type: dict
        suboptions:
            allowed_sub_vlans:
                description:
                    - Sub-VLANs allowed to egress this interface.
                type: str
            allowed_vlans:
                description:
                    - Allowed VLANs.
                type: str
            arp_inspection_trust:
                description:
                    - Dynamic ARP Inspection (trusted or untrusted).
                type: str
                choices:
                    - trusted
                    - untrusted
            auto_discovery_fortilink:
                description:
                    - Enable/disable automatic FortiLink discovery mode.
                type: str
                choices:
                    - disable
                    - enable
            auto_discovery_fortilink_packet_interval:
                description:
                    - FortiLink packet interval for automatic discovery (3 - 300 sec).
                type: int
            default_cos:
                description:
                    - Set default COS for untagged packets.
                type: int
            description:
                description:
                    - Description.
                type: str
            dhcp_snoop_learning_limit:
                description:
                    - Maximum DHCP IP learned on the interface.
                type: int
            dhcp_snoop_learning_limit_check:
                description:
                    - Enable/Disable DHCP learning limit check on the interface.
                type: str
                choices:
                    - disable
                    - enable
            dhcp_snoop_option82_trust:
                description:
                    - Enable/Disable (allow/disallow) dhcp pkt with option82 on untrusted interface.
                type: str
                choices:
                    - enable
                    - disable
            dhcp_snooping:
                description:
                    - DHCP snooping interface (trusted or untrusted).
                type: str
                choices:
                    - trusted
                    - untrusted
            discard_mode:
                description:
                    - Configure discard mode for interface.
                type: str
                choices:
                    - none
                    - all-tagged
                    - all-untagged
            edge_port:
                description:
                    - Enable/disable interface as edge port.
                type: str
                choices:
                    - enabled
                    - disabled
            filter_sub_vlans:
                description:
                    - Private VLAN or sub-VLAN based port type.
                type: str
                choices:
                    - disable
                    - enable
            fortilink_l3_mode:
                description:
                    - FortiLink L3 uplink port.
                type: str
                choices:
                    - enable
                    - disable
            igmp_snooping_flood_reports:
                description:
                    - Enable/disable flooding of IGMP snooping reports to this interface.
                type: str
                choices:
                    - enable
                    - disable
            ip_mac_binding:
                description:
                    - Enable/disable ip-mac-binding on this interaface.
                type: str
                choices:
                    - global
                    - enable
                    - disable
            learning_limit:
                description:
                    - Limit the number of dynamic MAC addresses on this port.
                type: int
            log_mac_event:
                description:
                    - Enable/disable logging for dynamic MAC address events.
                type: str
                choices:
                    - enable
                    - disable
            loop_guard:
                description:
                    - Enable/disable loop guard protection.
                type: str
                choices:
                    - enabled
                    - disabled
            loop_guard_mac_move_threshold:
                description:
                    - Trigger loop guard if MAC move per second of this interface reaches this threshold.
                type: int
            loop_guard_timeout:
                description:
                    - Loop guard disabling protection (min).
                type: int
            mcast_snooping_flood_traffic:
                description:
                    - Enable/disable flooding of multicast snooping traffic to this interface.
                type: str
                choices:
                    - enable
                    - disable
            mld_snooping_flood_reports:
                description:
                    - Enable/disable flooding of MLD reports to this interface.
                type: str
                choices:
                    - enable
                    - disable
            nac:
                description:
                    - Enable/disable NAC in Fortilink mode.
                type: str
                choices:
                    - enable
                    - disable
            name:
                description:
                    - Interface name.
                required: true
                type: str
            native_vlan:
                description:
                    - Native (untagged) VLAN.
                type: int
            packet_sample_rate:
                description:
                    - Packet sample rate (0 - 99999).
                type: int
            packet_sampler:
                description:
                    - Enable/disable packet sampling.
                type: str
                choices:
                    - enabled
                    - disabled
            port_security:
                description:
                    - Configure port security.
                type: dict
                suboptions:
                    allow_mac_move:
                        description:
                            - Enable/disable allow mac move mode.
                        type: str
                        choices:
                            - disable
                            - enable
                    auth_fail_vlan:
                        description:
                            - Enable/disable auth_fail vlan.
                        type: str
                        choices:
                            - disable
                            - enable
                    auth_fail_vlanid:
                        description:
                            - Set auth_fail vlanid.
                        type: int
                    authserver_timeout_period:
                        description:
                            - Set authserver_timeout period.
                        type: int
                    authserver_timeout_vlan:
                        description:
                            - Enable/disable authserver_timeout vlan.
                        type: str
                        choices:
                            - disable
                            - enable
                    authserver_timeout_vlanid:
                        description:
                            - Set authserver_timeout vlanid.
                        type: int
                    eap_auto_untagged_vlans:
                        description:
                            - Enable/disable EAP auto-untagged-vlans mode.
                        type: str
                        choices:
                            - disable
                            - enable
                    eap_egress_tagged:
                        description:
                            - Enable/disable Egress frame tag.
                        type: str
                        choices:
                            - disable
                            - enable
                    eap_passthru:
                        description:
                            - Enable/disable EAP pass-through mode.
                        type: str
                        choices:
                            - disable
                            - enable
                    framevid_apply:
                        description:
                            - Enable/disable the capbility to apply the EAP/MAB frame vlan to the port native vlan.
                        type: str
                        choices:
                            - disable
                            - enable
                    guest_auth_delay:
                        description:
                            - Set guest auth delay.
                        type: int
                    guest_vlan:
                        description:
                            - Enable/disable guest vlan.
                        type: str
                        choices:
                            - disable
                            - enable
                    guest_vlanid:
                        description:
                            - Set guest vlanid.
                        type: int
                    mab_eapol_request:
                        description:
                            - Set MAB EAPOL Request.
                        type: int
                    mac_auth_bypass:
                        description:
                            - Enable/disable mac-authentication-bypass on this interaface.
                        type: str
                        choices:
                            - disable
                            - enable
                    macsec_profile:
                        description:
                            - macsec port profile. Source switch.macsec.profile.name.
                        type: str
                    open_auth:
                        description:
                            - Enable/disable open authentication on this interaface.
                        type: str
                        choices:
                            - disable
                            - enable
                    port_security_mode:
                        description:
                            - Security mode.
                        type: str
                        choices:
                            - none
                            - 802.1X
                            - 802.1X-mac-based
                            - macsec
                    quarantine_vlan:
                        description:
                            - Enable/disable Quarantine VLAN detection.
                        type: str
                        choices:
                            - disable
                            - enable
                    radius_timeout_overwrite:
                        description:
                            - Enable/disable radius server session timeout to overwrite local timeout.
                        type: str
                        choices:
                            - disable
                            - enable
            primary_vlan:
                description:
                    - Private VLAN to host. Source switch.vlan.id.
                type: int
            private_vlan:
                description:
                    - Configure private VLAN.
                type: str
                choices:
                    - disable
                    - promiscuous
                    - sub-vlan
            private_vlan_port_type:
                description:
                    - Private VLAN or sub-VLAN based port type.
                type: int
            ptp_policy:
                description:
                    - PTP policy. Source switch.ptp.policy.name.
                type: str
            qnq:
                description:
                    - Configure QinQ.
                type: dict
                suboptions:
                    add_inner:
                        description:
                            - Add inner-tag for untagged packets upon ingress.
                        type: int
                    edge_type:
                        description:
                            - Choose edge type.
                        type: str
                        choices:
                            - customer
                    priority:
                        description:
                            - Follow S-Tag or C-Tag"s priority.
                        type: str
                        choices:
                            - follow-c-tag
                            - follow-s-tag
                    remove_inner:
                        description:
                            - Remove inner-tag upon egress.
                        type: str
                        choices:
                            - disable
                            - enable
                    s_tag_priority:
                        description:
                            - Set priority value if packets follow S-Tag"s priority.
                        type: int
                    status:
                        description:
                            - Enable/Disable QinQ mode.
                        type: str
                        choices:
                            - disable
                            - enable
                    stp_qnq_admin:
                        description:
                            - Enable/Disable QnQ to manage STP admin status.
                        type: str
                        choices:
                            - disable
                            - enable
                    untagged_s_vlan:
                        description:
                            - Add s-vlan to untagged packet.
                        type: int
                    vlan_mapping:
                        description:
                            - Configure Vlan Mapping.
                        type: list
                        suboptions:
                            description:
                                description:
                                    - Description of Mapping entry.
                                type: str
                            id:
                                description:
                                    - Entry Id.
                                required: true
                                type: int
                            match_c_vlan:
                                description:
                                    - Matching customer(inner) vlan.
                                type: int
                            new_s_vlan:
                                description:
                                    - Set new service vlan.
                                type: int
                    vlan_mapping_miss_drop:
                        description:
                            - Enabled or disabled drop if mapping missed.
                        type: str
                        choices:
                            - disable
                            - enable
            qos_policy:
                description:
                    - QOS egress COS queue policy. Source switch.qos.qos-policy.name.
                type: str
            raguard:
                description:
                    - IPV6 RA guard configuration.
                type: list
                suboptions:
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    raguard_policy:
                        description:
                            - RA Guard policy name. Source switch.raguard-policy.name.
                        type: str
                    vlan_list:
                        description:
                            - Vlan list.
                        type: str
            rpvst_port:
                description:
                    - Enable/disable interface to inter-op with pvst
                type: str
                choices:
                    - enabled
                    - disabled
            sample_direction:
                description:
                    - SFlow sample direction.
                type: str
                choices:
                    - tx
                    - rx
                    - both
            security_groups:
                description:
                    - Group name.
                type: list
                suboptions:
                    name:
                        description:
                            - Group name.
                        required: true
                        type: str
            sflow_counter_interval:
                description:
                    - 'SFlow sampler counter polling interval (0:disable - 255).'
                type: int
            snmp_index:
                description:
                    - SNMP index.
                type: int
            sticky_mac:
                description:
                    - Enable/disable Sticky MAC for this interface.
                type: str
                choices:
                    - enable
                    - disable
            stp_bpdu_guard:
                description:
                    - Enable/disable STP BPDU guard protection (stp-state and edge-port must be enabled).
                type: str
                choices:
                    - enabled
                    - disabled
            stp_bpdu_guard_timeout:
                description:
                    - BPDU Guard disabling protection (min).
                type: int
            stp_loop_protection:
                description:
                    - Enable/disable spanning tree protocol loop guard protection (stp-state must be enabled).
                type: str
                choices:
                    - enabled
                    - disabled
            stp_root_guard:
                description:
                    - Enable/disable STP root guard protection (stp-state must be enabled).
                type: str
                choices:
                    - enabled
                    - disabled
            stp_state:
                description:
                    - Enable/disable spanning tree protocol.
                type: str
                choices:
                    - enabled
                    - disabled
            sub_vlan:
                description:
                    - Private VLAN sub-VLAN to host. Source switch.vlan.id.
                type: int
            switch_port_mode:
                description:
                    - Enable/disable port as L2 switch port (enable) or as pure routed port (disable).
                type: str
                choices:
                    - disable
                    - enable
            trust_dot1p_map:
                description:
                    - QOS trust 802.1p map. Source switch.qos.dot1p-map.name.
                type: str
            trust_ip_dscp_map:
                description:
                    - QOS trust IP-DSCP map. Source switch.qos.ip-dscp-map.name.
                type: str
            type:
                description:
                    - Interface type.
                type: str
                choices:
                    - physical
                    - trunk
            untagged_vlans:
                description:
                    - Configure VLANs permitted to be transmitted without VLAN tags.
                type: str
            vlan_mapping:
                description:
                    - Configure vlan mapping table.
                type: list
                suboptions:
                    action:
                        description:
                            - Vlan action if packet is matched.
                        type: str
                        choices:
                            - add
                            - replace
                            - delete
                    description:
                        description:
                            - Description of Mapping entry.
                        type: str
                    direction:
                        description:
                            - Ingress or Egress direction.
                        type: str
                        choices:
                            - ingress
                            - egress
                    id:
                        description:
                            - Entry Id.
                        required: true
                        type: int
                    match_c_vlan:
                        description:
                            - Matching customer(inner) vlan.
                        type: int
                    match_s_vlan:
                        description:
                            - Matching service(outer) vlan.
                        type: int
                    new_s_vlan:
                        description:
                            - Set new service(outer) vlan.
                        type: int
            vlan_mapping_miss_drop:
                description:
                    - Enabled or disabled drop if mapping missed.
                type: str
                choices:
                    - disable
                    - enable
            vlan_tpid:
                description:
                    - Configure ether-type. Source switch.vlan-tpid.name.
                type: str
            vlan_traffic_type:
                description:
                    - Configure traffic tagging.
                type: str
                choices:
                    - untagged
                    - tagged
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
  - name: Usable interfaces (trunks and ports).
    fortiswitch_switch_interface:
      state: "present"
      switch_interface:
        allowed_sub_vlans: "<your_own_value>"
        allowed_vlans: "<your_own_value>"
        arp_inspection_trust: "trusted"
        auto_discovery_fortilink: "disable"
        auto_discovery_fortilink_packet_interval: "7"
        default_cos: "8"
        description: "<your_own_value>"
        dhcp_snoop_learning_limit: "10"
        dhcp_snoop_learning_limit_check: "disable"
        dhcp_snoop_option82_trust: "enable"
        dhcp_snooping: "trusted"
        discard_mode: "none"
        edge_port: "enabled"
        filter_sub_vlans: "disable"
        fortilink_l3_mode: "enable"
        igmp_snooping_flood_reports: "enable"
        ip_mac_binding: "global"
        learning_limit: "20"
        log_mac_event: "enable"
        loop_guard: "enabled"
        loop_guard_mac_move_threshold: "23"
        loop_guard_timeout: "24"
        mcast_snooping_flood_traffic: "enable"
        mld_snooping_flood_reports: "enable"
        nac: "enable"
        name: "default_name_28"
        native_vlan: "29"
        packet_sample_rate: "30"
        packet_sampler: "enabled"
        port_security:
            allow_mac_move: "disable"
            auth_fail_vlan: "disable"
            auth_fail_vlanid: "35"
            authserver_timeout_period: "36"
            authserver_timeout_vlan: "disable"
            authserver_timeout_vlanid: "38"
            eap_auto_untagged_vlans: "disable"
            eap_egress_tagged: "disable"
            eap_passthru: "disable"
            framevid_apply: "disable"
            guest_auth_delay: "43"
            guest_vlan: "disable"
            guest_vlanid: "45"
            mab_eapol_request: "46"
            mac_auth_bypass: "disable"
            macsec_profile: "<your_own_value> (source switch.macsec.profile.name)"
            open_auth: "disable"
            port_security_mode: "none"
            quarantine_vlan: "disable"
            radius_timeout_overwrite: "disable"
        primary_vlan: "53 (source switch.vlan.id)"
        private_vlan: "disable"
        private_vlan_port_type: "55"
        ptp_policy: "<your_own_value> (source switch.ptp.policy.name)"
        qnq:
            add_inner: "58"
            edge_type: "customer"
            priority: "follow-c-tag"
            remove_inner: "disable"
            s_tag_priority: "62"
            status: "disable"
            stp_qnq_admin: "disable"
            untagged_s_vlan: "65"
            vlan_mapping:
             -
                description: "<your_own_value>"
                id:  "68"
                match_c_vlan: "69"
                new_s_vlan: "70"
            vlan_mapping_miss_drop: "disable"
        qos_policy: "<your_own_value> (source switch.qos.qos-policy.name)"
        raguard:
         -
            id:  "74"
            raguard_policy: "<your_own_value> (source switch.raguard-policy.name)"
            vlan_list: "<your_own_value>"
        rpvst_port: "enabled"
        sample_direction: "tx"
        security_groups:
         -
            name: "default_name_80"
        sflow_counter_interval: "81"
        snmp_index: "82"
        sticky_mac: "enable"
        stp_bpdu_guard: "enabled"
        stp_bpdu_guard_timeout: "85"
        stp_loop_protection: "enabled"
        stp_root_guard: "enabled"
        stp_state: "enabled"
        sub_vlan: "89 (source switch.vlan.id)"
        switch_port_mode: "disable"
        trust_dot1p_map: "<your_own_value> (source switch.qos.dot1p-map.name)"
        trust_ip_dscp_map: "<your_own_value> (source switch.qos.ip-dscp-map.name)"
        type: "physical"
        untagged_vlans: "<your_own_value>"
        vlan_mapping:
         -
            action: "add"
            description: "<your_own_value>"
            direction: "ingress"
            id:  "99"
            match_c_vlan: "100"
            match_s_vlan: "101"
            new_s_vlan: "102"
        vlan_mapping_miss_drop: "disable"
        vlan_tpid: "<your_own_value> (source switch.vlan-tpid.name)"
        vlan_traffic_type: "untagged"

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


def filter_switch_interface_data(json):
    option_list = ['allowed_sub_vlans', 'allowed_vlans', 'arp_inspection_trust',
                   'auto_discovery_fortilink', 'auto_discovery_fortilink_packet_interval', 'default_cos',
                   'description', 'dhcp_snoop_learning_limit', 'dhcp_snoop_learning_limit_check',
                   'dhcp_snoop_option82_trust', 'dhcp_snooping', 'discard_mode',
                   'edge_port', 'filter_sub_vlans', 'fortilink_l3_mode',
                   'igmp_snooping_flood_reports', 'ip_mac_binding', 'learning_limit',
                   'log_mac_event', 'loop_guard', 'loop_guard_mac_move_threshold',
                   'loop_guard_timeout', 'mcast_snooping_flood_traffic', 'mld_snooping_flood_reports',
                   'nac', 'name', 'native_vlan',
                   'packet_sample_rate', 'packet_sampler', 'port_security',
                   'primary_vlan', 'private_vlan', 'private_vlan_port_type',
                   'ptp_policy', 'qnq', 'qos_policy',
                   'raguard', 'rpvst_port', 'sample_direction',
                   'security_groups', 'sflow_counter_interval', 'snmp_index',
                   'sticky_mac', 'stp_bpdu_guard', 'stp_bpdu_guard_timeout',
                   'stp_loop_protection', 'stp_root_guard', 'stp_state',
                   'sub_vlan', 'switch_port_mode', 'trust_dot1p_map',
                   'trust_ip_dscp_map', 'type', 'untagged_vlans',
                   'vlan_mapping', 'vlan_mapping_miss_drop', 'vlan_tpid',
                   'vlan_traffic_type']
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


def switch_interface(data, fos):

    state = data['state']

    switch_interface_data = data['switch_interface']
    filtered_data = underscore_to_hyphen(filter_switch_interface_data(switch_interface_data))

    if state == "present" or state is True:
        return fos.set('switch',
                       'interface',
                       data=filtered_data,
                       )

    elif state == "absent":
        return fos.delete('switch',
                          'interface',
                          mkey=filtered_data['name'])
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_switch(data, fos):

    fos.do_member_operation('switch_interface')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['switch_interface']:
        resp = switch_interface(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_interface'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "native_vlan": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "stp_bpdu_guard": {
            "type": "string",
            "options": [
                {
                    "value": "enabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "arp_inspection_trust": {
            "type": "string",
            "options": [
                {
                    "value": "trusted",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "untrusted",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "sflow_counter_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "vlan_traffic_type": {
            "type": "string",
            "options": [
                {
                    "value": "untagged",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "tagged",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "dhcp_snooping": {
            "type": "string",
            "options": [
                {
                    "value": "trusted",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "untrusted",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "primary_vlan": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "packet_sampler": {
            "type": "string",
            "options": [
                {
                    "value": "enabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "raguard": {
            "type": "list",
            "children": {
                "raguard_policy": {
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
                },
                "vlan_list": {
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
        "stp_loop_protection": {
            "type": "string",
            "options": [
                {
                    "value": "enabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "loop_guard_timeout": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "untagged_vlans": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "private_vlan": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "promiscuous",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "sub-vlan",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "switch_port_mode": {
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
        "allowed_vlans": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "security_groups": {
            "type": "list",
            "children": {
                "name": {
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
        "description": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "sample_direction": {
            "type": "string",
            "options": [
                {
                    "value": "tx",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "rx",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "both",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "nac": {
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
        "mld_snooping_flood_reports": {
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
        "stp_state": {
            "type": "string",
            "options": [
                {
                    "value": "enabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "mcast_snooping_flood_traffic": {
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
        "vlan_tpid": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "dhcp_snoop_option82_trust": {
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
        "trust_ip_dscp_map": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "sub_vlan": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "discard_mode": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "all-tagged",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "all-untagged",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "fortilink_l3_mode": {
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
        "dhcp_snoop_learning_limit": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "loop_guard_mac_move_threshold": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "edge_port": {
            "type": "string",
            "options": [
                {
                    "value": "enabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
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
                    "value": "trunk",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "stp_bpdu_guard_timeout": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "allowed_sub_vlans": {
            "type": "string",
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
        "qnq": {
            "type": "dict",
            "children": {
                "status": {
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
                "s_tag_priority": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vlan_mapping": {
                    "type": "list",
                    "children": {
                        "description": {
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
                        },
                        "new_s_vlan": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "match_c_vlan": {
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
                "untagged_s_vlan": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "remove_inner": {
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
                "vlan_mapping_miss_drop": {
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
                "priority": {
                    "type": "string",
                    "options": [
                        {
                            "value": "follow-c-tag",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "follow-s-tag",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "stp_qnq_admin": {
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
                "edge_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "customer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "add_inner": {
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
        "auto_discovery_fortilink_packet_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "auto_discovery_fortilink": {
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
        "default_cos": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "ip_mac_binding": {
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
        "log_mac_event": {
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
        "port_security": {
            "type": "dict",
            "children": {
                "authserver_timeout_vlanid": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "framevid_apply": {
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
                "authserver_timeout_period": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "eap_auto_untagged_vlans": {
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
                "allow_mac_move": {
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
                "auth_fail_vlanid": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "eap_passthru": {
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
                "port_security_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "802.1X",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "802.1X-mac-based",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "macsec",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "guest_auth_delay": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "authserver_timeout_vlan": {
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
                "auth_fail_vlan": {
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
                "quarantine_vlan": {
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
                "guest_vlan": {
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
                "macsec_profile": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "mab_eapol_request": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "radius_timeout_overwrite": {
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
                "open_auth": {
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
                "eap_egress_tagged": {
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
                "mac_auth_bypass": {
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
                "guest_vlanid": {
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
        "filter_sub_vlans": {
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
        "rpvst_port": {
            "type": "string",
            "options": [
                {
                    "value": "enabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "loop_guard": {
            "type": "string",
            "options": [
                {
                    "value": "enabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "private_vlan_port_type": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "stp_root_guard": {
            "type": "string",
            "options": [
                {
                    "value": "enabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
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
        "vlan_mapping": {
            "type": "list",
            "children": {
                "direction": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ingress",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "egress",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
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
                "match_s_vlan": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "new_s_vlan": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "match_c_vlan": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "add",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "replace",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "delete",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
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
        },
        "igmp_snooping_flood_reports": {
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
        "vlan_mapping_miss_drop": {
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
        "packet_sample_rate": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "sticky_mac": {
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
        "learning_limit": {
            "type": "integer",
            "revisions": {
                "v7.0.0": True
            }
        },
        "trust_dot1p_map": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "ptp_policy": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "dhcp_snoop_learning_limit_check": {
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
        "qos_policy": {
            "type": "string",
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
        "switch_interface": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_interface"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_interface"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_interface")

        is_error, has_changed, result = fortiswitch_switch(module.params, fos)

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
