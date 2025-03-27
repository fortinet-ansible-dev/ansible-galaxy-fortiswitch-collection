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
module: fortiswitch_switch_interface
short_description: Usable interfaces (trunks and ports) in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch feature and interface category.
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
    switch_interface:
        description:
            - Usable interfaces (trunks and ports).
        default: null
        type: dict
        suboptions:
            allow_arp_monitor:
                description:
                    - Enable/Disable ARP monitoring.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
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
                    - 'trusted'
                    - 'untrusted'
            auto_discovery_fortilink:
                description:
                    - Enable/disable automatic FortiLink discovery mode.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
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
                    - 'disable'
                    - 'enable'
            dhcp_snoop_option82_override:
                description:
                    - Configure per vlan option82 override.
                type: list
                elements: dict
                suboptions:
                    circuit_id:
                        description:
                            - Text String of Circuit Id.
                        type: str
                    id:
                        description:
                            - Vlan Id.
                        type: int
                    remote_id:
                        description:
                            - Text String of Remote Id.
                        type: str
            dhcp_snoop_option82_trust:
                description:
                    - Enable/Disable (allow/disallow) dhcp pkt with option82 on untrusted interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp_snooping:
                description:
                    - DHCP snooping interface (trusted or untrusted).
                type: str
                choices:
                    - 'trusted'
                    - 'untrusted'
            discard_mode:
                description:
                    - Configure discard mode for interface.
                type: str
                choices:
                    - 'none'
                    - 'all-tagged'
                    - 'all-untagged'
            edge_port:
                description:
                    - Enable/disable interface as edge port.
                type: str
                choices:
                    - 'enabled'
                    - 'disabled'
            filter_sub_vlans:
                description:
                    - Private VLAN or sub-VLAN based port type.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            fortilink_l3_mode:
                description:
                    - FortiLink L3 uplink port.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            igmp_snooping_flood_reports:
                description:
                    - Enable/disable flooding of IGMP snooping reports to this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            interface_mode:
                description:
                    - Set interface mode - L2 or L3.
                type: str
                choices:
                    - 'L2'
                    - 'L3'
            ip_mac_binding:
                description:
                    - Enable/disable ip-mac-binding on this interaface.
                type: str
                choices:
                    - 'global'
                    - 'enable'
                    - 'disable'
            learning_limit:
                description:
                    - Limit the number of dynamic MAC addresses on this port.
                type: int
            learning_limit_action:
                description:
                    - Enable/disable turning off this interface on learn limit violation.
                type: str
                choices:
                    - 'none'
                    - 'shutdown'
            log_mac_event:
                description:
                    - Enable/disable logging for dynamic MAC address events.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            loop_guard:
                description:
                    - Enable/disable loop guard protection.
                type: str
                choices:
                    - 'enabled'
                    - 'disabled'
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
                    - 'enable'
                    - 'disable'
            mld_snooping_flood_reports:
                description:
                    - Enable/disable flooding of MLD reports to this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            nac:
                description:
                    - Enable/disable NAC in Fortilink mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
                    - 'enabled'
                    - 'disabled'
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
                            - 'disable'
                            - 'enable'
                    allow_mac_move_to:
                        description:
                            - Enable/disable allow mac move mode to this port.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    auth_fail_vlan:
                        description:
                            - Enable/disable auth_fail vlan.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    auth_fail_vlanid:
                        description:
                            - Set auth_fail vlanid.
                        type: int
                    auth_order:
                        description:
                            - set authentication auth order.
                        type: str
                        choices:
                            - 'dot1x-MAB'
                            - 'MAB-dot1x'
                            - 'MAB'
                    auth_priority:
                        description:
                            - set authentication auth priority.
                        type: str
                        choices:
                            - 'legacy'
                            - 'dot1x-MAB'
                            - 'MAB-dot1x'
                    authserver_timeout_period:
                        description:
                            - Set authserver_timeout period.
                        type: int
                    authserver_timeout_tagged:
                        description:
                            - Set authserver_timeout tagged vlan mode.
                        type: str
                        choices:
                            - 'disable'
                            - 'lldp-voice'
                            - 'static'
                    authserver_timeout_tagged_lldp_voice_vlanid:
                        description:
                            - authserver_timeout tagged lldp voice vlanid.
                        type: int
                    authserver_timeout_tagged_vlanid:
                        description:
                            - Set authserver_timeout tagged vlanid.
                        type: int
                    authserver_timeout_vlan:
                        description:
                            - Enable/disable authserver_timeout vlan.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    authserver_timeout_vlanid:
                        description:
                            - Set authserver_timeout vlanid.
                        type: int
                    dacl:
                        description:
                            - Enable/disable dynamic access control list mode.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    eap_auto_untagged_vlans:
                        description:
                            - Enable/disable EAP auto-untagged-vlans mode.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    eap_egress_tagged:
                        description:
                            - Enable/disable Egress frame tag.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    eap_passthru:
                        description:
                            - Enable/disable EAP pass-through mode.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    framevid_apply:
                        description:
                            - Enable/disable the capbility to apply the EAP/MAB frame vlan to the port native vlan.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    guest_auth_delay:
                        description:
                            - Set guest auth delay.
                        type: int
                    guest_vlan:
                        description:
                            - Enable/disable guest vlan.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
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
                            - 'disable'
                            - 'enable'
                    macsec_pae_mode:
                        description:
                            - Assign PAE mode to a MACSEC interface.
                        type: str
                        choices:
                            - 'none'
                            - 'supp'
                            - 'auth'
                    macsec_profile:
                        description:
                            - macsec port profile.
                        type: str
                    open_auth:
                        description:
                            - Enable/disable open authentication on this interaface.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    port_security_mode:
                        description:
                            - Security mode.
                        type: str
                        choices:
                            - 'none'
                            - '802.1X'
                            - '802.1X-mac-based'
                            - 'macsec'
                    quarantine_vlan:
                        description:
                            - Enable/disable Quarantine VLAN detection.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    radius_timeout_overwrite:
                        description:
                            - Enable/disable radius server session timeout to overwrite local timeout.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            primary_vlan:
                description:
                    - Private VLAN to host.
                type: int
            private_vlan:
                description:
                    - Configure private VLAN.
                type: str
                choices:
                    - 'disable'
                    - 'promiscuous'
                    - 'sub-vlan'
            private_vlan_port_type:
                description:
                    - Private VLAN or sub-VLAN based port type.
                type: int
            ptp_policy:
                description:
                    - PTP policy.
                type: str
            ptp_status:
                description:
                    - PTP Admin. Status.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            qnq:
                description:
                    - Configure QinQ.
                type: dict
                suboptions:
                    add_inner:
                        description:
                            - Add inner-tag for untagged packets upon ingress.
                        type: int
                    allowed_c_vlan:
                        description:
                            - Allowed c vlans.
                        type: str
                    edge_type:
                        description:
                            - Choose edge type.
                        type: str
                        choices:
                            - 'customer'
                    native_c_vlan:
                        description:
                            - Native c vlan for untagged packets.
                        type: int
                    priority:
                        description:
                            - Follow S-Tag or C-Tag"s priority.
                        type: str
                        choices:
                            - 'follow-c-tag'
                            - 'follow-s-tag'
                    remove_inner:
                        description:
                            - Remove inner-tag upon egress.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    s_tag_priority:
                        description:
                            - Set priority value if packets follow S-Tag"s priority.
                        type: int
                    status:
                        description:
                            - Enable/Disable QinQ mode.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    stp_qnq_admin:
                        description:
                            - Enable/Disable QnQ to manage STP admin status.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    untagged_s_vlan:
                        description:
                            - Add s-vlan to untagged packet.
                        type: int
                    vlan_mapping:
                        description:
                            - Configure Vlan Mapping.
                        type: list
                        elements: dict
                        suboptions:
                            description:
                                description:
                                    - Description of Mapping entry.
                                type: str
                            id:
                                description:
                                    - Entry Id.
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
                            - 'disable'
                            - 'enable'
            qos_policy:
                description:
                    - QOS egress COS queue policy.
                type: str
            raguard:
                description:
                    - IPV6 RA guard configuration.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID.
                        type: int
                    raguard_policy:
                        description:
                            - RA Guard policy name.
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
                    - 'enabled'
                    - 'disabled'
            sample_direction:
                description:
                    - SFlow sample direction.
                type: str
                choices:
                    - 'tx'
                    - 'rx'
                    - 'both'
            security_groups:
                description:
                    - Group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Group name.
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
                    - 'enable'
                    - 'disable'
            stp_bpdu_guard:
                description:
                    - Enable/disable STP BPDU guard protection (stp-state and edge-port must be enabled).
                type: str
                choices:
                    - 'enabled'
                    - 'disabled'
            stp_bpdu_guard_timeout:
                description:
                    - BPDU Guard disabling protection (min).
                type: int
            stp_loop_protection:
                description:
                    - Enable/disable spanning tree protocol loop guard protection (stp-state must be enabled).
                type: str
                choices:
                    - 'enabled'
                    - 'disabled'
            stp_root_guard:
                description:
                    - Enable/disable STP root guard protection (stp-state must be enabled).
                type: str
                choices:
                    - 'enabled'
                    - 'disabled'
            stp_state:
                description:
                    - Enable/disable spanning tree protocol.
                type: str
                choices:
                    - 'enabled'
                    - 'disabled'
            sub_vlan:
                description:
                    - Private VLAN sub-VLAN to host.
                type: int
            switch_port_mode:
                description:
                    - Enable/disable port as L2 switch port (enable) or as pure routed port (disable).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            trust_dot1p_map:
                description:
                    - QOS trust 802.1p map.
                type: str
            trust_ip_dscp_map:
                description:
                    - QOS trust IP-DSCP map.
                type: str
            type:
                description:
                    - Interface type.
                type: str
                choices:
                    - 'physical'
                    - 'trunk'
            untagged_vlans:
                description:
                    - Configure VLANs permitted to be transmitted without VLAN tags.
                type: str
            vlan_mapping:
                description:
                    - Configure vlan mapping table.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Vlan action if packet is matched.
                        type: str
                        choices:
                            - 'add'
                            - 'replace'
                            - 'delete'
                    description:
                        description:
                            - Description of Mapping entry.
                        type: str
                    direction:
                        description:
                            - Ingress or Egress direction.
                        type: str
                        choices:
                            - 'ingress'
                            - 'egress'
                    id:
                        description:
                            - Entry Id.
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
                    - 'disable'
                    - 'enable'
            vlan_tpid:
                description:
                    - Configure ether-type.
                type: str
            vlan_traffic_type:
                description:
                    - Configure traffic tagging.
                type: str
                choices:
                    - 'untagged'
                    - 'tagged'
"""

EXAMPLES = """
- name: Usable interfaces (trunks and ports).
  fortinet.fortiswitch.fortiswitch_switch_interface:
      state: "present"
      switch_interface:
          allow_arp_monitor: "disable"
          allowed_sub_vlans: "<your_own_value>"
          allowed_vlans: "<your_own_value>"
          arp_inspection_trust: "trusted"
          auto_discovery_fortilink: "disable"
          auto_discovery_fortilink_packet_interval: "150"
          default_cos: "9"
          description: "<your_own_value>"
          dhcp_snoop_learning_limit: "11"
          dhcp_snoop_learning_limit_check: "disable"
          dhcp_snoop_option82_override:
              -
                  circuit_id: "<your_own_value>"
                  id: "15 (source switch.vlan.id)"
                  remote_id: "<your_own_value>"
          dhcp_snoop_option82_trust: "enable"
          dhcp_snooping: "trusted"
          discard_mode: "none"
          edge_port: "enabled"
          filter_sub_vlans: "disable"
          fortilink_l3_mode: "enable"
          igmp_snooping_flood_reports: "enable"
          interface_mode: "L2"
          ip_mac_binding: "global"
          learning_limit: "26"
          learning_limit_action: "none"
          log_mac_event: "enable"
          loop_guard: "enabled"
          loop_guard_mac_move_threshold: "30"
          loop_guard_timeout: "31"
          mcast_snooping_flood_traffic: "enable"
          mld_snooping_flood_reports: "enable"
          nac: "enable"
          name: "default_name_35"
          native_vlan: "36"
          packet_sample_rate: "37"
          packet_sampler: "enabled"
          port_security:
              allow_mac_move: "disable"
              allow_mac_move_to: "disable"
              auth_fail_vlan: "disable"
              auth_fail_vlanid: "43"
              auth_order: "dot1x-MAB"
              auth_priority: "legacy"
              authserver_timeout_period: "46"
              authserver_timeout_tagged: "disable"
              authserver_timeout_tagged_lldp_voice_vlanid: "48"
              authserver_timeout_tagged_vlanid: "49"
              authserver_timeout_vlan: "disable"
              authserver_timeout_vlanid: "51"
              dacl: "disable"
              eap_auto_untagged_vlans: "disable"
              eap_egress_tagged: "disable"
              eap_passthru: "disable"
              framevid_apply: "disable"
              guest_auth_delay: "57"
              guest_vlan: "disable"
              guest_vlanid: "59"
              mab_eapol_request: "60"
              mac_auth_bypass: "disable"
              macsec_pae_mode: "none"
              macsec_profile: "<your_own_value> (source switch.macsec.profile.name)"
              open_auth: "disable"
              port_security_mode: "none"
              quarantine_vlan: "disable"
              radius_timeout_overwrite: "disable"
          primary_vlan: "68 (source switch.vlan.id)"
          private_vlan: "disable"
          private_vlan_port_type: "70"
          ptp_policy: "<your_own_value> (source switch.ptp.policy.name)"
          ptp_status: "enable"
          qnq:
              add_inner: "2047"
              allowed_c_vlan: "<your_own_value>"
              edge_type: "customer"
              native_c_vlan: "2047"
              priority: "follow-c-tag"
              remove_inner: "disable"
              s_tag_priority: "3"
              status: "disable"
              stp_qnq_admin: "disable"
              untagged_s_vlan: "2047"
              vlan_mapping:
                  -
                      description: "<your_own_value>"
                      id: "86"
                      match_c_vlan: "2047"
                      new_s_vlan: "2047"
              vlan_mapping_miss_drop: "disable"
          qos_policy: "<your_own_value> (source switch.qos.qos-policy.name)"
          raguard:
              -
                  id: "92"
                  raguard_policy: "<your_own_value> (source switch.raguard-policy.name)"
                  vlan_list: "<your_own_value>"
          rpvst_port: "enabled"
          sample_direction: "tx"
          security_groups:
              -
                  name: "default_name_98"
          sflow_counter_interval: "127"
          snmp_index: "100"
          sticky_mac: "enable"
          stp_bpdu_guard: "enabled"
          stp_bpdu_guard_timeout: "103"
          stp_loop_protection: "enabled"
          stp_root_guard: "enabled"
          stp_state: "enabled"
          sub_vlan: "107 (source switch.vlan.id)"
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
                  id: "117"
                  match_c_vlan: "2047"
                  match_s_vlan: "2047"
                  new_s_vlan: "2047"
          vlan_mapping_miss_drop: "disable"
          vlan_tpid: "<your_own_value> (source switch.vlan-tpid.name)"
          vlan_traffic_type: "untagged"
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
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortiswitch.plugins.module_utils.fortiswitch.comparison import (
    find_current_values,
)


def filter_switch_interface_data(json):
    option_list = [
        "allow_arp_monitor",
        "allowed_sub_vlans",
        "allowed_vlans",
        "arp_inspection_trust",
        "auto_discovery_fortilink",
        "auto_discovery_fortilink_packet_interval",
        "default_cos",
        "description",
        "dhcp_snoop_learning_limit",
        "dhcp_snoop_learning_limit_check",
        "dhcp_snoop_option82_override",
        "dhcp_snoop_option82_trust",
        "dhcp_snooping",
        "discard_mode",
        "edge_port",
        "filter_sub_vlans",
        "fortilink_l3_mode",
        "igmp_snooping_flood_reports",
        "interface_mode",
        "ip_mac_binding",
        "learning_limit",
        "learning_limit_action",
        "log_mac_event",
        "loop_guard",
        "loop_guard_mac_move_threshold",
        "loop_guard_timeout",
        "mcast_snooping_flood_traffic",
        "mld_snooping_flood_reports",
        "nac",
        "name",
        "native_vlan",
        "packet_sample_rate",
        "packet_sampler",
        "port_security",
        "primary_vlan",
        "private_vlan",
        "private_vlan_port_type",
        "ptp_policy",
        "ptp_status",
        "qnq",
        "qos_policy",
        "raguard",
        "rpvst_port",
        "sample_direction",
        "security_groups",
        "sflow_counter_interval",
        "snmp_index",
        "sticky_mac",
        "stp_bpdu_guard",
        "stp_bpdu_guard_timeout",
        "stp_loop_protection",
        "stp_root_guard",
        "stp_state",
        "sub_vlan",
        "switch_port_mode",
        "trust_dot1p_map",
        "trust_ip_dscp_map",
        "type",
        "untagged_vlans",
        "vlan_mapping",
        "vlan_mapping_miss_drop",
        "vlan_tpid",
        "vlan_traffic_type",
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


def switch_interface(data, fos, check_mode=False):
    state = data.get("state", None)

    switch_interface_data = data["switch_interface"]

    filtered_data = filter_switch_interface_data(switch_interface_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("switch", "interface", filtered_data)
        current_data = fos.get("switch", "interface", mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and isinstance(current_data.get("results"), list)
            and len(current_data["results"]) > 0
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            mkeyname = fos.get_mkeyname(None, None)
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)

            # handle global modules'
            if mkeyname is None and state is None:
                is_same = is_same_comparison(
                    serialize(current_data["results"]), serialize(copied_filtered_data)
                )

                current_values = find_current_values(
                    copied_filtered_data, current_data["results"]
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": copied_filtered_data},
                )

            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]),
                    serialize(copied_filtered_data),
                )

                current_values = find_current_values(
                    copied_filtered_data, current_data["results"][0]
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": copied_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}

    if state == "present" or state is True:
        return fos.set(
            "switch",
            "interface",
            data=filtered_data,
        )

    elif state == "absent":
        return fos.delete("switch", "interface", mkey=filtered_data["name"])
    else:
        fos._module.fail_json(msg="state must be present or absent!")


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


def fortiswitch_switch(data, fos, check_mode):
    fos.do_member_operation("switch", "interface")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["switch_interface"]:
        resp = switch_interface(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("switch_interface"))
    if check_mode:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp) and current_cmdb_index != resp["cmdb-index"],
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "fortilink_l3_mode": {
            "v_range": [["v7.0.0", "v7.0.6"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "fortilink-l3-mode",
            "help": "FortiLink L3 uplink port.",
            "category": "unitary",
        },
        "igmp_snooping_flood_reports": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "igmp-snooping-flood-reports",
            "help": "Enable/disable flooding of IGMP snooping reports to this interface.",
            "category": "unitary",
        },
        "auto_discovery_fortilink": {
            "v_range": [["v7.0.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
            "name": "auto-discovery-fortilink",
            "help": "Enable/disable automatic FortiLink discovery mode.",
            "category": "unitary",
        },
        "trust_dot1p_map": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trust-dot1p-map",
            "help": "QOS trust 802.1p map.",
            "category": "unitary",
        },
        "discard_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "all-tagged"},
                {"value": "all-untagged"},
            ],
            "name": "discard-mode",
            "help": "Configure discard mode for interface.",
            "category": "unitary",
        },
        "qos_policy": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "qos-policy",
            "help": "QOS egress COS queue policy.",
            "category": "unitary",
        },
        "arp_inspection_trust": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "trusted"}, {"value": "untrusted"}],
            "name": "arp-inspection-trust",
            "help": "Dynamic ARP Inspection (trusted or untrusted).",
            "category": "unitary",
        },
        "security_groups": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Group name.",
                    "category": "unitary",
                }
            },
            "v_range": [["v7.0.0", ""]],
            "name": "security-groups",
            "help": "Group name.",
            "mkey": "name",
            "category": "table",
        },
        "private_vlan": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "promiscuous"},
                {"value": "sub-vlan"},
            ],
            "name": "private-vlan",
            "help": "Configure private VLAN.",
            "category": "unitary",
        },
        "sub_vlan": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "sub-vlan",
            "help": "Private VLAN sub-VLAN to host.",
            "category": "unitary",
        },
        "allowed_sub_vlans": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "allowed-sub-vlans",
            "help": "Sub-VLANs allowed to egress this interface.",
            "category": "unitary",
        },
        "sample_direction": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "tx"}, {"value": "rx"}, {"value": "both"}],
            "name": "sample-direction",
            "help": "SFlow sample direction.",
            "category": "unitary",
        },
        "dhcp_snoop_option82_trust": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "dhcp-snoop-option82-trust",
            "help": "Enable/Disable (allow/disallow) dhcp pkt with option82 on untrusted interface.",
            "category": "unitary",
        },
        "edge_port": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enabled"}, {"value": "disabled"}],
            "name": "edge-port",
            "help": "Enable/disable interface as edge port.",
            "category": "unitary",
        },
        "stp_bpdu_guard": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enabled"}, {"value": "disabled"}],
            "name": "stp-bpdu-guard",
            "help": "Enable/disable STP BPDU guard protection (stp-state and edge-port must be enabled).",
            "category": "unitary",
        },
        "loop_guard": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enabled"}, {"value": "disabled"}],
            "name": "loop-guard",
            "help": "Enable/disable loop guard protection.",
            "category": "unitary",
        },
        "qnq": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "status",
                    "help": "Enable/Disable QinQ mode.",
                    "category": "unitary",
                },
                "vlan_mapping": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "new_s_vlan": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "new-s-vlan",
                            "help": "Set new service vlan.",
                            "category": "unitary",
                        },
                        "match_c_vlan": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "match-c-vlan",
                            "help": "Matching customer(inner) vlan.",
                            "category": "unitary",
                        },
                        "id": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "integer",
                            "name": "id",
                            "help": "Entry Id.",
                            "category": "unitary",
                        },
                        "description": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "name": "description",
                            "help": "Description of Mapping entry.",
                            "category": "unitary",
                        },
                    },
                    "v_range": [["v7.0.0", ""]],
                    "name": "vlan-mapping",
                    "help": "Configure Vlan Mapping.",
                    "mkey": "id",
                    "category": "table",
                },
                "stp_qnq_admin": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "stp-qnq-admin",
                    "help": "Enable/Disable QnQ to manage STP admin status.",
                    "category": "unitary",
                },
                "remove_inner": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "remove-inner",
                    "help": "Remove inner-tag upon egress.",
                    "category": "unitary",
                },
                "priority": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "follow-c-tag"}, {"value": "follow-s-tag"}],
                    "name": "priority",
                    "help": "Follow S-Tag or C-Tag's priority.",
                    "category": "unitary",
                },
                "vlan_mapping_miss_drop": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "vlan-mapping-miss-drop",
                    "help": "Enabled or disabled drop if mapping missed.",
                    "category": "unitary",
                },
                "untagged_s_vlan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "untagged-s-vlan",
                    "help": "Add s-vlan to untagged packet.",
                    "category": "unitary",
                },
                "add_inner": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "add-inner",
                    "help": "Add inner-tag for untagged packets upon ingress.",
                    "category": "unitary",
                },
                "edge_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "customer"}],
                    "name": "edge-type",
                    "help": "Choose edge type.",
                    "category": "unitary",
                },
                "s_tag_priority": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "s-tag-priority",
                    "help": "Set priority value if packets follow S-Tag's priority.",
                    "category": "unitary",
                },
                "native_c_vlan": {
                    "v_range": [],
                    "type": "integer",
                    "name": "native-c-vlan",
                    "help": "Native c vlan for untagged packets.",
                    "category": "unitary",
                },
                "allowed_c_vlan": {
                    "v_range": [],
                    "type": "string",
                    "name": "allowed-c-vlan",
                    "help": "Allowed c vlans.",
                    "category": "unitary",
                },
            },
            "name": "qnq",
            "help": "Configure QinQ.",
            "category": "complex",
        },
        "allowed_vlans": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "allowed-vlans",
            "help": "Allowed VLANs.",
            "category": "unitary",
        },
        "nac": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "nac",
            "help": "Enable/disable NAC in Fortilink mode.",
            "category": "unitary",
        },
        "auto_discovery_fortilink_packet_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "auto-discovery-fortilink-packet-interval",
            "help": "FortiLink packet interval for automatic discovery (3 - 300 sec).",
            "category": "unitary",
        },
        "primary_vlan": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "primary-vlan",
            "help": "Private VLAN to host.",
            "category": "unitary",
        },
        "vlan_mapping": {
            "type": "list",
            "elements": "dict",
            "children": {
                "direction": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "ingress"}, {"value": "egress"}],
                    "name": "direction",
                    "help": "Ingress or Egress direction.",
                    "category": "unitary",
                },
                "description": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "description",
                    "help": "Description of Mapping entry.",
                    "category": "unitary",
                },
                "match_s_vlan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "match-s-vlan",
                    "help": "Matching service(outer) vlan.",
                    "category": "unitary",
                },
                "new_s_vlan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "new-s-vlan",
                    "help": "Set new service(outer) vlan.",
                    "category": "unitary",
                },
                "action": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "add"},
                        {"value": "replace"},
                        {"value": "delete"},
                    ],
                    "name": "action",
                    "help": "Vlan action if packet is matched.",
                    "category": "unitary",
                },
                "match_c_vlan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "match-c-vlan",
                    "help": "Matching customer(inner) vlan.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Entry Id.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "vlan-mapping",
            "help": "Configure vlan mapping table.",
            "mkey": "id",
            "category": "table",
        },
        "raguard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vlan_list": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "vlan-list",
                    "help": "Vlan list.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "ID.",
                    "category": "unitary",
                },
                "raguard_policy": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "raguard-policy",
                    "help": "RA Guard policy name.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "raguard",
            "help": "IPV6 RA guard configuration.",
            "mkey": "id",
            "category": "table",
        },
        "stp_bpdu_guard_timeout": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "stp-bpdu-guard-timeout",
            "help": "BPDU Guard disabling protection (min).",
            "category": "unitary",
        },
        "stp_loop_protection": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enabled"}, {"value": "disabled"}],
            "name": "stp-loop-protection",
            "help": "Enable/disable spanning tree protocol loop guard protection (stp-state must be enabled).",
            "category": "unitary",
        },
        "learning_limit": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "learning-limit",
            "help": "Limit the number of dynamic MAC addresses on this port.",
            "category": "unitary",
        },
        "loop_guard_mac_move_threshold": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "loop-guard-mac-move-threshold",
            "help": "Trigger loop guard if MAC move per second of this interface reaches this threshold.",
            "category": "unitary",
        },
        "log_mac_event": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "log-mac-event",
            "help": "Enable/disable logging for dynamic MAC address events.",
            "category": "unitary",
        },
        "dhcp_snoop_learning_limit": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "dhcp-snoop-learning-limit",
            "help": "Maximum DHCP IP learned on the interface.",
            "category": "unitary",
        },
        "type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "physical"}, {"value": "trunk"}],
            "name": "type",
            "help": "Interface type.",
            "category": "unitary",
        },
        "snmp_index": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "snmp-index",
            "help": "SNMP index.",
            "category": "unitary",
        },
        "dhcp_snoop_learning_limit_check": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
            "name": "dhcp-snoop-learning-limit-check",
            "help": "Enable/Disable DHCP learning limit check on the interface.",
            "category": "unitary",
        },
        "switch_port_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
            "name": "switch-port-mode",
            "help": "Enable/disable port as L2 switch port (enable) or as pure routed port (disable).",
            "category": "unitary",
        },
        "description": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "description",
            "help": "Description.",
            "category": "unitary",
        },
        "stp_state": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enabled"}, {"value": "disabled"}],
            "name": "stp-state",
            "help": "Enable/disable spanning tree protocol.",
            "category": "unitary",
        },
        "vlan_traffic_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "untagged"}, {"value": "tagged"}],
            "name": "vlan-traffic-type",
            "help": "Configure traffic tagging.",
            "category": "unitary",
        },
        "sticky_mac": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "sticky-mac",
            "help": "Enable/disable Sticky MAC for this interface.",
            "category": "unitary",
        },
        "packet_sampler": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enabled"}, {"value": "disabled"}],
            "name": "packet-sampler",
            "help": "Enable/disable packet sampling.",
            "category": "unitary",
        },
        "loop_guard_timeout": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "loop-guard-timeout",
            "help": "Loop guard disabling protection (min).",
            "category": "unitary",
        },
        "rpvst_port": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enabled"}, {"value": "disabled"}],
            "name": "rpvst-port",
            "help": "Enable/disable interface to inter-op with pvst",
            "category": "unitary",
        },
        "ip_mac_binding": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "global"}, {"value": "enable"}, {"value": "disable"}],
            "name": "ip-mac-binding",
            "help": "Enable/disable ip-mac-binding on this interaface.",
            "category": "unitary",
        },
        "mld_snooping_flood_reports": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "mld-snooping-flood-reports",
            "help": "Enable/disable flooding of MLD reports to this interface.",
            "category": "unitary",
        },
        "sflow_counter_interval": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "sflow-counter-interval",
            "help": "SFlow sampler counter polling interval (0:disable - 255).",
            "category": "unitary",
        },
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "Interface name.",
            "category": "unitary",
        },
        "native_vlan": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "native-vlan",
            "help": "Native (untagged) VLAN.",
            "category": "unitary",
        },
        "vlan_mapping_miss_drop": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
            "name": "vlan-mapping-miss-drop",
            "help": "Enabled or disabled drop if mapping missed.",
            "category": "unitary",
        },
        "untagged_vlans": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "untagged-vlans",
            "help": "Configure VLANs permitted to be transmitted without VLAN tags.",
            "category": "unitary",
        },
        "private_vlan_port_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "private-vlan-port-type",
            "help": "Private VLAN or sub-VLAN based port type.",
            "category": "unitary",
        },
        "dhcp_snooping": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "trusted"}, {"value": "untrusted"}],
            "name": "dhcp-snooping",
            "help": "DHCP snooping interface (trusted or untrusted).",
            "category": "unitary",
        },
        "filter_sub_vlans": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
            "name": "filter-sub-vlans",
            "help": "Private VLAN or sub-VLAN based port type.",
            "category": "unitary",
        },
        "stp_root_guard": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enabled"}, {"value": "disabled"}],
            "name": "stp-root-guard",
            "help": "Enable/disable STP root guard protection (stp-state must be enabled).",
            "category": "unitary",
        },
        "trust_ip_dscp_map": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "trust-ip-dscp-map",
            "help": "QOS trust IP-DSCP map.",
            "category": "unitary",
        },
        "port_security": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "auth_fail_vlan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "auth-fail-vlan",
                    "help": "Enable/disable auth_fail vlan.",
                    "category": "unitary",
                },
                "macsec_profile": {
                    "v_range": [["v7.0.0", "v7.2.4"]],
                    "type": "string",
                    "name": "macsec-profile",
                    "help": "macsec port profile.",
                    "category": "unitary",
                },
                "auth_fail_vlanid": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "auth-fail-vlanid",
                    "help": "Set auth_fail vlanid.",
                    "category": "unitary",
                },
                "port_security_mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "802.1X"},
                        {"value": "802.1X-mac-based"},
                        {"value": "macsec"},
                    ],
                    "name": "port-security-mode",
                    "help": "Security mode.",
                    "category": "unitary",
                },
                "mab_eapol_request": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "mab-eapol-request",
                    "help": "Set MAB EAPOL Request.",
                    "category": "unitary",
                },
                "authserver_timeout_vlan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "authserver-timeout-vlan",
                    "help": "Enable/disable authserver_timeout vlan.",
                    "category": "unitary",
                },
                "allow_mac_move": {
                    "v_range": [["v7.0.0", "v7.2.2"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "allow-mac-move",
                    "help": "Enable/disable allow mac move mode.",
                    "category": "unitary",
                },
                "guest_vlan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "guest-vlan",
                    "help": "Enable/disable guest vlan.",
                    "category": "unitary",
                },
                "guest_auth_delay": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "guest-auth-delay",
                    "help": "Set guest auth delay.",
                    "category": "unitary",
                },
                "framevid_apply": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "framevid-apply",
                    "help": "Enable/disable the capbility to apply the EAP/MAB frame vlan to the port native vlan.",
                    "category": "unitary",
                },
                "eap_auto_untagged_vlans": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "eap-auto-untagged-vlans",
                    "help": "Enable/disable EAP auto-untagged-vlans mode.",
                    "category": "unitary",
                },
                "mac_auth_bypass": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "mac-auth-bypass",
                    "help": "Enable/disable mac-authentication-bypass on this interaface.",
                    "category": "unitary",
                },
                "radius_timeout_overwrite": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "radius-timeout-overwrite",
                    "help": "Enable/disable radius server session timeout to overwrite local timeout.",
                    "category": "unitary",
                },
                "authserver_timeout_period": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "authserver-timeout-period",
                    "help": "Set authserver_timeout period.",
                    "category": "unitary",
                },
                "open_auth": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "open-auth",
                    "help": "Enable/disable open authentication on this interaface.",
                    "category": "unitary",
                },
                "authserver_timeout_vlanid": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "authserver-timeout-vlanid",
                    "help": "Set authserver_timeout vlanid.",
                    "category": "unitary",
                },
                "quarantine_vlan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "quarantine-vlan",
                    "help": "Enable/disable Quarantine VLAN detection.",
                    "category": "unitary",
                },
                "guest_vlanid": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "name": "guest-vlanid",
                    "help": "Set guest vlanid.",
                    "category": "unitary",
                },
                "eap_egress_tagged": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "eap-egress-tagged",
                    "help": "Enable/disable Egress frame tag.",
                    "category": "unitary",
                },
                "eap_passthru": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "eap-passthru",
                    "help": "Enable/disable EAP pass-through mode.",
                    "category": "unitary",
                },
                "dacl": {
                    "v_range": [["v7.0.3", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "dacl",
                    "help": "Enable/disable dynamic access control list mode.",
                    "category": "unitary",
                },
                "macsec_pae_mode": {
                    "v_range": [["v7.2.1", "v7.2.4"]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "supp"},
                        {"value": "auth"},
                    ],
                    "name": "macsec-pae-mode",
                    "help": "Assign PAE mode to a MACSEC interface.",
                    "category": "unitary",
                },
                "auth_priority": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "legacy"},
                        {"value": "dot1x-MAB"},
                        {"value": "MAB-dot1x"},
                    ],
                    "name": "auth-priority",
                    "help": "set authentication auth priority.",
                    "category": "unitary",
                },
                "auth_order": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "dot1x-MAB"},
                        {"value": "MAB-dot1x"},
                        {"value": "MAB", "v_range": [["v7.2.3", ""]]},
                    ],
                    "name": "auth-order",
                    "help": "set authentication auth order.",
                    "category": "unitary",
                },
                "allow_mac_move_to": {
                    "v_range": [["v7.2.3", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                    "name": "allow-mac-move-to",
                    "help": "Enable/disable allow mac move mode to this port.",
                    "category": "unitary",
                },
                "authserver_timeout_tagged_lldp_voice_vlanid": {
                    "v_range": [],
                    "type": "integer",
                    "name": "authserver-timeout-tagged-lldp-voice-vlanid",
                    "help": "authserver_timeout tagged lldp voice vlanid.",
                    "category": "unitary",
                },
                "authserver_timeout_tagged_vlanid": {
                    "v_range": [],
                    "type": "integer",
                    "name": "authserver-timeout-tagged-vlanid",
                    "help": "Set authserver_timeout tagged vlanid.",
                    "category": "unitary",
                },
                "authserver_timeout_tagged": {
                    "v_range": [],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "lldp-voice"},
                        {"value": "static"},
                    ],
                    "name": "authserver-timeout-tagged",
                    "help": "Set authserver_timeout tagged vlan mode.",
                    "category": "unitary",
                },
            },
            "name": "port-security",
            "help": "Configure port security.",
            "category": "complex",
        },
        "default_cos": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "default-cos",
            "help": "Set default COS for untagged packets.",
            "category": "unitary",
        },
        "mcast_snooping_flood_traffic": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "mcast-snooping-flood-traffic",
            "help": "Enable/disable flooding of multicast snooping traffic to this interface.",
            "category": "unitary",
        },
        "vlan_tpid": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "vlan-tpid",
            "help": "Configure ether-type.",
            "category": "unitary",
        },
        "packet_sample_rate": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "packet-sample-rate",
            "help": "Packet sample rate (0 - 99999).",
            "category": "unitary",
        },
        "ptp_policy": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "ptp-policy",
            "help": "PTP policy.",
            "category": "unitary",
        },
        "learning_limit_action": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "shutdown"}],
            "name": "learning-limit-action",
            "help": "Enable/disable turning off this interface on learn limit violation.",
            "category": "unitary",
        },
        "interface_mode": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "L2"}, {"value": "L3"}],
            "name": "interface-mode",
            "help": "Set interface mode - L2 or L3.",
            "category": "unitary",
        },
        "dhcp_snoop_option82_override": {
            "type": "list",
            "elements": "dict",
            "children": {
                "circuit_id": {
                    "v_range": [["v7.2.2", ""]],
                    "type": "string",
                    "name": "circuit-id",
                    "help": "Text String of Circuit Id.",
                    "category": "unitary",
                },
                "id": {
                    "v_range": [["v7.2.2", ""]],
                    "type": "integer",
                    "name": "id",
                    "help": "Vlan Id.",
                    "category": "unitary",
                },
                "remote_id": {
                    "v_range": [["v7.2.2", ""]],
                    "type": "string",
                    "name": "remote-id",
                    "help": "Text String of Remote Id.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.2.2", ""]],
            "name": "dhcp-snoop-option82-override",
            "help": "Configure per vlan option82 override.",
            "mkey": "id",
            "category": "table",
        },
        "ptp_status": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "ptp-status",
            "help": "PTP Admin. Status.",
            "category": "unitary",
        },
        "allow_arp_monitor": {
            "v_range": [],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
            "name": "allow-arp-monitor",
            "help": "Enable/Disable ARP monitoring.",
            "category": "unitary",
        },
    },
    "v_range": [["v7.0.0", ""]],
    "name": "interface",
    "help": "Usable interfaces (trunks and ports).",
    "mkey": "name",
    "category": "table",
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
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "switch_interface": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_interface"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_interface"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

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
            fos, versioned_schema, "switch_interface"
        )
        is_error, has_changed, result, diff = fortiswitch_switch(
            module.params, fos, module.check_mode
        )
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
