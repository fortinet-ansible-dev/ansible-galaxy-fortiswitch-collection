![Fortinet logo|](https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/Fortinet_logo.svg/320px-Fortinet_logo.svg.png)

## FortiSwitch Ansible Collection
***

The collection is the FortiSwitch Ansible Automation project. It includes the modules that are able to configure FortiSwitch. 

## Installation
This collection is distributed via [ansible-galaxy](https://galaxy.ansible.com/), the installation steps are as follows:

1. Install or upgrade to Ansible 2.11
2. Download this collection from galaxy: `ansible-galaxy collection install fortinet.fortiswitch:1.0.1`

## Requirements
* Ansible 2.11 is required to support the newer Ansible Collections format

## Supported FortiSwitch Versions
| FSW version|Galaxy  Version| Release date|Path to Install |
|----------|:-------------:|:-------------:|:------:|

__Note__: Use `-f` option (i.e. `ansible-galaxy collection install -f fortinet.fortiswitch:x.x.x`) to renew your existing local installation.


## Modules
The collection provides the following modules:


* `fortiswitch_alertemail_setting` Alertemail setting configuration in Fortinet's FortiSwitch
* `fortiswitch_configuration_fact` Retrieve Facts of FortiSwitch Configurable Objects.
* `fortiswitch_export_config_playbook` Convert the returned facts into a playbook.
* `fortiswitch_gui_console` Dashboard CLI console configuration in Fortinet's FortiSwitch
* `fortiswitch_log_custom_field` Custom field configuation in Fortinet's FortiSwitch
* `fortiswitch_log_disk_filter` Filters for local disk logging in Fortinet's FortiSwitch
* `fortiswitch_log_disk_setting` Settings for local disk logging in Fortinet's FortiSwitch
* `fortiswitch_log_eventfilter` Log event filter configuration in Fortinet's FortiSwitch
* `fortiswitch_log_fortianalyzer2_filter` Filters for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_log_fortianalyzer2_setting` Setting for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_log_fortianalyzer3_filter` Filters for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_log_fortianalyzer3_setting` Setting for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_log_fortianalyzer_filter` Filters for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_log_fortianalyzer_override_filter` Override filters for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_log_fortianalyzer_override_setting` Setting for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_log_fortianalyzer_setting` Setting for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_log_fortiguard_setting` Settings for FortiGuard Analysis Service in Fortinet's FortiSwitch
* `fortiswitch_log_gui` Logging device to display in GUI in Fortinet's FortiSwitch
* `fortiswitch_log_memory_filter` Filters for memory buffer in Fortinet's FortiSwitch
* `fortiswitch_log_memory_global_setting` Global settings for memory log in Fortinet's FortiSwitch
* `fortiswitch_log_memory_setting` Settings for memory buffer in Fortinet's FortiSwitch
* `fortiswitch_log_remote_setting` Settings for remote logging in Fortinet's FortiSwitch
* `fortiswitch_log_syslogd2_filter` Filters for remote system server in Fortinet's FortiSwitch
* `fortiswitch_log_syslogd2_setting` Settings for remote syslog server in Fortinet's FortiSwitch
* `fortiswitch_log_syslogd3_filter` Filters for remote system server in Fortinet's FortiSwitch
* `fortiswitch_log_syslogd3_setting` Settings for remote syslog server in Fortinet's FortiSwitch
* `fortiswitch_log_syslogd_filter` Filters for remote system server in Fortinet's FortiSwitch
* `fortiswitch_log_syslogd_override_filter` Override filters for remote system server in Fortinet's FortiSwitch
* `fortiswitch_log_syslogd_override_setting` Settings for remote syslog server in Fortinet's FortiSwitch
* `fortiswitch_log_syslogd_setting` Settings for remote syslog server in Fortinet's FortiSwitch
* `fortiswitch_monitor_fact` Retrieve Facts of FortiSwitch Monitor Objects.
* `fortiswitch_router_access_list6` IPv6 access list configuration in Fortinet's FortiSwitch
* `fortiswitch_router_access_list` Access list configuration in Fortinet's FortiSwitch
* `fortiswitch_router_aspath_list` AS path list configuration in Fortinet's FortiSwitch
* `fortiswitch_router_auth_path` Auth-based routing configuration in Fortinet's FortiSwitch
* `fortiswitch_router_bgp` BGP configuration in Fortinet's FortiSwitch
* `fortiswitch_router_community_list` Community list configuration in Fortinet's FortiSwitch
* `fortiswitch_router_gwdetect` Gwdetect in Fortinet's FortiSwitch
* `fortiswitch_router_isis` ISIS configuration in Fortinet's FortiSwitch
* `fortiswitch_router_key_chain` Key-chain configuration in Fortinet's FortiSwitch
* `fortiswitch_router_multicast_flow` Multicast-flow configuration in Fortinet's FortiSwitch
* `fortiswitch_router_multicast` Router multicast configuration in Fortinet's FortiSwitch
* `fortiswitch_router_ospf6` Router OSPF6 configuration in Fortinet's FortiSwitch
* `fortiswitch_router_ospf` OSPF configuration in Fortinet's FortiSwitch
* `fortiswitch_router_policy` Policy routing configuration in Fortinet's FortiSwitch
* `fortiswitch_router_prefix_list6` IPv6 prefix list configuration in Fortinet's FortiSwitch
* `fortiswitch_router_prefix_list` Prefix list configuration in Fortinet's FortiSwitch
* `fortiswitch_router_ripng` router ripng configuratio in Fortinet's FortiSwitch
* `fortiswitch_router_rip` RIP configuration in Fortinet's FortiSwitch
* `fortiswitch_router_route_map` Route map configuration in Fortinet's FortiSwitch
* `fortiswitch_router_setting` Set rib settings in Fortinet's FortiSwitch
* `fortiswitch_router_static6` Ipv6 static routes configuration in Fortinet's FortiSwitch
* `fortiswitch_router_static` IPv4 static routes configuration in Fortinet's FortiSwitch
* `fortiswitch_router_vrf` VRF configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_acl_802_1x` 802-1X Radius Dynamic Ingress Policy configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_acl_egress` Egress Policy configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_acl_ingress` Ingress Policy configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_acl_policer` Policer configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_acl_prelookup` Prelookup Policy configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_acl_service_custom` Custom service configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_acl_settings` Configure access-control lists global settings on Switch in Fortinet's FortiSwitch
* `fortiswitch_switch_auto_isl_port_group` Auto ISL port group in Fortinet's FortiSwitch
* `fortiswitch_switch_auto_network` Auto network in Fortinet's FortiSwitch
* `fortiswitch_switch_controller_global` Switch-controller global configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_domain` Switch forwarding domains in Fortinet's FortiSwitch
* `fortiswitch_switch_global` Configure global settings in Fortinet's FortiSwitch
* `fortiswitch_switch_igmp_snooping_globals` Configure igmp-snooping on Switch in Fortinet's FortiSwitch
* `fortiswitch_switch_interface` Usable interfaces (trunks and ports) in Fortinet's FortiSwitch
* `fortiswitch_switch_ip_mac_binding` Ip-mac-binding table in Fortinet's FortiSwitch
* `fortiswitch_switch_lldp_profile` LLDP configuration profiles in Fortinet's FortiSwitch
* `fortiswitch_switch_lldp_settings` Global LLDP configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_macsec_profile` MACsec configuration profiles in Fortinet's FortiSwitch
* `fortiswitch_switch_mirror` Packet mirror in Fortinet's FortiSwitch
* `fortiswitch_switch_mld_snooping_globals` Configure mld-snooping on Switch in Fortinet's FortiSwitch
* `fortiswitch_switch_network_monitor_directed` Configuration of the static entries for network monitoring on the switch in Fortinet's FortiSwitch
* `fortiswitch_switch_network_monitor_settings` Global configuration of network monitoring on the switch in Fortinet's FortiSwitch
* `fortiswitch_switch_phy_mode` PHY configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_physical_port` Physical port specific configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_ptp_policy` PTP policy configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_ptp_settings` Global PTP configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_qos_dot1p_map` QOS 802.1p configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_qos_ip_dscp_map` QOS IP precedence/DSCP configuration in Fortinet's FortiSwitch
* `fortiswitch_switch_qos_qos_policy` QOS egress policy in Fortinet's FortiSwitch
* `fortiswitch_switch_quarantine` Configure quarantine devices on the switch in Fortinet's FortiSwitch
* `fortiswitch_switch_raguard_policy` IPV6 RA Guard policy in Fortinet's FortiSwitch
* `fortiswitch_switch_security_feature` Switch security feature control nobs in Fortinet's FortiSwitch
* `fortiswitch_switch_static_mac` Switch static mac address entries in Fortinet's FortiSwitch
* `fortiswitch_switch_storm_control` Configure excess switch traffic (storm control) in Fortinet's FortiSwitch
* `fortiswitch_switch_stp_instance` Stp instances in Fortinet's FortiSwitch
* `fortiswitch_switch_stp_settings` Switch-global stp settings in Fortinet's FortiSwitch
* `fortiswitch_switch_trunk` Link-aggregation in Fortinet's FortiSwitch
* `fortiswitch_switch_virtual_wire` Configure virtual wire in Fortinet's FortiSwitch
* `fortiswitch_switch_vlan` Configure optional per-VLAN settings in Fortinet's FortiSwitch
* `fortiswitch_switch_vlan_tpid` Configure switch global ether-types in Fortinet's FortiSwitch
* `fortiswitch_system_accprofile` Configure system administrative access group in Fortinet's FortiSwitch
* `fortiswitch_system_admin` Administrative user configuration in Fortinet's FortiSwitch
* `fortiswitch_system_alarm` Alarm configuration in Fortinet's FortiSwitch
* `fortiswitch_system_alertemail` Alert e-mail mail server configuration in Fortinet's FortiSwitch
* `fortiswitch_system_alias_command` Alias command definitions in Fortinet's FortiSwitch
* `fortiswitch_system_alias_group` Groups of alias commands in Fortinet's FortiSwitch
* `fortiswitch_system_arp_table` Configure arp table in Fortinet's FortiSwitch
* `fortiswitch_system_autoupdate_clientoverride` Configure client override for the FDN in Fortinet's FortiSwitch
* `fortiswitch_system_autoupdate_override` Configure override FDS server in Fortinet's FortiSwitch
* `fortiswitch_system_autoupdate_push_update` Configure push updates in Fortinet's FortiSwitch
* `fortiswitch_system_autoupdate_schedule` Configure update schedule in Fortinet's FortiSwitch
* `fortiswitch_system_autoupdate_tunneling` Configure web proxy tunneling for the FDN in Fortinet's FortiSwitch
* `fortiswitch_system_bug_report` Configure bug report in Fortinet's FortiSwitch
* `fortiswitch_system_central_management` Central management configuration in Fortinet's FortiSwitch
* `fortiswitch_system_certificate_ca` CA certificate in Fortinet's FortiSwitch
* `fortiswitch_system_certificate_crl` Certificate Revokation List in Fortinet's FortiSwitch
* `fortiswitch_system_certificate_local` Local keys and certificates in Fortinet's FortiSwitch
* `fortiswitch_system_certificate_ocsp` Ocsp configuration in Fortinet's FortiSwitch
* `fortiswitch_system_certificate_remote` Remote certificate in Fortinet's FortiSwitch
* `fortiswitch_system_console` Configure console in Fortinet's FortiSwitch
* `fortiswitch_system_dhcp_server` Configure DHCP servers in Fortinet's FortiSwitch
* `fortiswitch_system_dns` Configure DNS in Fortinet's FortiSwitch
* `fortiswitch_system_dns_database` Dns-database in Fortinet's FortiSwitch
* `fortiswitch_system_dns_server` Dns-server in Fortinet's FortiSwitch
* `fortiswitch_system_flan_cloud` FortiLAN cloud manager configuration in Fortinet's FortiSwitch
* `fortiswitch_system_flow_export` System Flow Export settings in Fortinet's FortiSwitch
* `fortiswitch_system_fm` Fm in Fortinet's FortiSwitch
* `fortiswitch_system_fortianalyzer2` Setting for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_system_fortianalyzer3` Setting for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_system_fortianalyzer` Setting for FortiAnalyzer in Fortinet's FortiSwitch
* `fortiswitch_system_fortiguard` Configure FortiGuard services in Fortinet's FortiSwitch
* `fortiswitch_system_fortimanager` FortiManagerconfiguration in Fortinet's FortiSwitch
* `fortiswitch_system_fsw_cloud` FortiSwitch cloud manager configuration in Fortinet's FortiSwitch
* `fortiswitch_system_global` Configure global range attributes in Fortinet's FortiSwitch
* `fortiswitch_system_interface` Configure interfaces in Fortinet's FortiSwitch
* `fortiswitch_system_ipv6_neighbor_cache` Configure IPv6 neighbor cache table in Fortinet's FortiSwitch
* `fortiswitch_system_link_monitor` Configure Link Health Monitor in Fortinet's FortiSwitch
* `fortiswitch_system_location` Configure Location table in Fortinet's FortiSwitch
* `fortiswitch_system_mac_address_table` Mac address table in Fortinet's FortiSwitch
* `fortiswitch_system_management_tunnel` Management tunnel configuration in Fortinet's FortiSwitch
* `fortiswitch_system_ntp` Ntp system info configuration in Fortinet's FortiSwitch
* `fortiswitch_system_object_tag` Object tags in Fortinet's FortiSwitch
* `fortiswitch_system_password_policy` Config password policy in Fortinet's FortiSwitch
* `fortiswitch_system_port_pair` Port-pair in Fortinet's FortiSwitch
* `fortiswitch_system_proxy_arp` Configure proxy-arp in Fortinet's FortiSwitch
* `fortiswitch_system_resource_limits` Resource limits configuration in Fortinet's FortiSwitch
* `fortiswitch_system_schedule_group` Schedule group configuration in Fortinet's FortiSwitch
* `fortiswitch_system_schedule_onetime` onetime schedule configuratio in Fortinet's FortiSwitch
* `fortiswitch_system_schedule_recurring` recurring schedule configuratio in Fortinet's FortiSwitch
* `fortiswitch_system_session_ttl` Session ttl configuration in Fortinet's FortiSwitch
* `fortiswitch_system_settings` Settings in Fortinet's FortiSwitch
* `fortiswitch_system_sflow` Configure sFlow in Fortinet's FortiSwitch
* `fortiswitch_system_sniffer_profile` Show packet sniffer configuration in Fortinet's FortiSwitch
* `fortiswitch_system_snmp_community` SNMP community configuration in Fortinet's FortiSwitch
* `fortiswitch_system_snmp_sysinfo` SNMP system info configuration in Fortinet's FortiSwitch
* `fortiswitch_system_snmp_user` SNMP user configuration in Fortinet's FortiSwitch
* `fortiswitch_system_tos_based_priority` Configure tos based priority table in Fortinet's FortiSwitch
* `fortiswitch_system_vdom_dns` Vdom dns configuration in Fortinet's FortiSwitch
* `fortiswitch_system_vdom_property` Vdom-property configuration in Fortinet's FortiSwitch
* `fortiswitch_system_vdom` Virtual domain configuration in Fortinet's FortiSwitch
* `fortiswitch_system_zone` Zone configuration in Fortinet's FortiSwitch
* `fortiswitch_user_group` User group configuration in Fortinet's FortiSwitch
* `fortiswitch_user_ldap` LDAP server entry configuration in Fortinet's FortiSwitch
* `fortiswitch_user_local` Local user configuration in Fortinet's FortiSwitch
* `fortiswitch_user_peer` config peer use in Fortinet's FortiSwitch
* `fortiswitch_user_peergrp` config peer's user grou in Fortinet's FortiSwitch
* `fortiswitch_user_radius` RADIUS server entry configuration in Fortinet's FortiSwitch
* `fortiswitch_user_setting` User authentication setting in Fortinet's FortiSwitch
* `fortiswitch_user_tacacsplus` TACACS+ server entry configuration in Fortinet's FortiSwitch

## Roles

## Usage
The following example is used to configure system interface in Fortinet's FortiSwitch.

Create `config_system_interface.yml` with the following template:
```yaml
---
- hosts: fortiswitch01
  collections:
  - fortinet.fortiswitch
  connection: httpapi
  gather_facts: 'no'
  vars:
    ansible_httpapi_use_ssl: 'yes'
    ansible_httpapi_validate_certs: 'no'
    ansible_httpapi_port: 443
  tasks:
  - name: edit internal interface
    fortiswitch_system_interface:
      state: present
      system_interface:
        name: internal
        vdom: root
        allowaccess: https
```
Create the `hosts` inventory file
```
[fortiswitches]
fortiswitch01 ansible_host=192.168.190.100 ansible_user="admin" ansible_password="password"

[fortiswitches:vars]
ansible_network_os=fortinet.fortiswitch.fortiswitch
```

Run the test:
```bash
ansible-playbook -i hosts config_system_interface.yml
```

The task will set up the allowaccess in system_interface.
