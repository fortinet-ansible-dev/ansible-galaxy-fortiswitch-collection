![Fortinet logo|](https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/Fortinet_logo.svg/320px-Fortinet_logo.svg.png)

# fortinet.fortiswitch - Configuring FortiSwitch

## Description

The collection includes modules that allow users to configure FortiSwitch, specifically for managing firewall features.
Please refer to https://ansible-galaxy-fortiswitch-docs.readthedocs.io/en/latest/index.html for more information.

## Requirements

- Ansible 2.15.0 or above
- Python 3.9 or above

## Installation
This collection is distributed via [ansible-galaxy](https://galaxy.ansible.com/).

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install fortinet.fortiswitch
```

You can also include it in a requirements.yml file and install it with ansible-galaxy collection install -r requirements.yml, using the format:


```yaml
collections:
  - name: fortinet.fortiswitch
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install fortinet.fortiswitch --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 1.2.4:

```
ansible-galaxy collection install fortinet.fortiswitch:==1.2.4
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

## Use Cases

The FortiSwitch collection supports only username/password authentication.

Follow the example here https://ansible-galaxy-fortiswitch-docs.readthedocs.io/en/latest/playbook.html to configure the hosts file and write your first playbook.

Configure the allowaccess for port1:
```yaml
tasks:
- name: configure the allowaccess for port1
  fortiswitch_system_interface:
    state: present
    system_interface:
      name: port1
      allowaccess:
        - https
        - http
        - ssh
        - ping
```

Run the playbook:
```bash
ansible-playbook configure_allowaccess_for_port1.yml
```

## Testing

Testing is conducted by the Fortinet team. The new version will be released once the entire collection passes both unit and sanity tests.

## Support

Please open a Github issue if your have any questions https://github.com/fortinet-ansible-dev/ansible-galaxy-fortiswitch-collection/issues

## Release Notes and Roadmap

Refer to the release notes here https://ansible-galaxy-fortiswitch-docs.readthedocs.io/en/latest/release.html
The FortiSwitch Ansible collection is scheduled to be updated every two months.

## Related Information

For more information, please refer to [Documentation](https://ansible-galaxy-fortiswitch-docs.readthedocs.io/en/latest/index.html)
| FSW version|Galaxy  Version| Release date|Path to Install |
|----------|:-------------:|:-------------:|:------:|
|7.0.0|1.0.0 |2021/12/15|`ansible-galaxy collection install fortinet.fortiswitch:1.0.0`|
|7.0.0|1.0.1 |2022/2/2|`ansible-galaxy collection install fortinet.fortiswitch:1.0.1`|
|7.0.0|1.1.0 `latest`|2022/4/1|`ansible-galaxy collection install fortinet.fortiswitch:1.1.0`|

__Note__: Use `-f` option (i.e. `ansible-galaxy collection install -f fortinet.fortiswitch:x.x.x`) to renew your existing local installation.


## Modules
The collection provides the following modules:


* `fortiswitch_alertemail_setting` Alertemail setting configuration in Fortinet's FortiSwitch
* `fortiswitch_configuration_fact` Retrieve Facts of FortiSwitch Configurable Objects.
* `fortiswitch_execute_backup_default_config` Backup Switch's Default Configuration.
* `fortiswitch_execute_backup_full_config` Backup Switch's Full Configuration.
* `fortiswitch_execute_backup_standalone_config` Backup Switch's Standalone Configuration.
* `fortiswitch_execute_download_sniffer_profile` Download sniffer profile.
* `fortiswitch_execute_sign_data` Sign data with a local certificate.
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
* `fortiswitch_router_rip` RIP configuration in Fortinet's FortiSwitch
* `fortiswitch_router_ripng` router ripng configuratio in Fortinet's FortiSwitch
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
* `fortiswitch_switch_vlan_pruning` Vlan Pruning in Fortinet's FortiSwitch
* `fortiswitch_switch_vlan_tpid` Configure switch global ether-types in Fortinet's FortiSwitch
* `fortiswitch_switch_vlan` Configure optional per-VLAN settings in Fortinet's FortiSwitch
* `fortiswitch_system_accprofile` Configure system administrative access group in Fortinet's FortiSwitch
* `fortiswitch_system_admin` Administrative user configuration in Fortinet's FortiSwitch
* `fortiswitch_system_alarm` Alarm configuration in Fortinet's FortiSwitch
* `fortiswitch_system_alertemail` Alert e-mail mail server configuration in Fortinet's FortiSwitch
* `fortiswitch_system_alias_command` Alias command definitions in Fortinet's FortiSwitch
* `fortiswitch_system_alias_group` Groups of alias commands in Fortinet's FortiSwitch
* `fortiswitch_system_arp_table` Configure arp table in Fortinet's FortiSwitch
* `fortiswitch_system_auto_script` Configure auto script in Fortinet's FortiSwitch
* `fortiswitch_system_automation_action` Action for automation stitches in Fortinet's FortiSwitch
* `fortiswitch_system_automation_destination` Automation destinations in Fortinet's FortiSwitch
* `fortiswitch_system_automation_stitch` Automation stitches in Fortinet's FortiSwitch
* `fortiswitch_system_automation_trigger` Trigger for automation stitches in Fortinet's FortiSwitch
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
* `fortiswitch_system_debug` Application and CLI debug values to set at startup and retain over reboot in Fortinet's FortiSwitch
* `fortiswitch_system_dhcp_server` Configure DHCP servers in Fortinet's FortiSwitch
* `fortiswitch_system_dns_database` Dns-database in Fortinet's FortiSwitch
* `fortiswitch_system_dns_server` Dns-server in Fortinet's FortiSwitch
* `fortiswitch_system_dns` Configure DNS in Fortinet's FortiSwitch
* `fortiswitch_system_email_server` Email server configuration in Fortinet's FortiSwitch
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
* `fortiswitch_system_ptp_interface_policy` PTP policy configuration in Fortinet's FortiSwitch
* `fortiswitch_system_ptp_profile` PTP policy configuration in Fortinet's FortiSwitch
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
* `fortiswitch_system_vxlan` Configure VXLAN devices in Fortinet's FortiSwitch
* `fortiswitch_system_web` Configure web attributes in Fortinet's FortiSwitch
* `fortiswitch_system_zone` Zone configuration in Fortinet's FortiSwitch
* `fortiswitch_user_group` User group configuration in Fortinet's FortiSwitch
* `fortiswitch_user_ldap` LDAP server entry configuration in Fortinet's FortiSwitch
* `fortiswitch_user_local` Local user configuration in Fortinet's FortiSwitch
* `fortiswitch_user_peer` config peer use in Fortinet's FortiSwitch
* `fortiswitch_user_peergrp` config peer's user grou in Fortinet's FortiSwitch
* `fortiswitch_user_radius` RADIUS server entry configuration in Fortinet's FortiSwitch
* `fortiswitch_user_setting` User authentication setting in Fortinet's FortiSwitch
* `fortiswitch_user_tacacsplus` TACACS+ server entry configuration in Fortinet's FortiSwitch

## License Information

FortiSwitch Ansible Collection follows [GNU General Public License v3.0](LICENSE).