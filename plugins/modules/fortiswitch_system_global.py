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
module: fortiswitch_system_global
short_description: Configure global range attributes in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and global category.
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
    - ansible>=2.14
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

    system_global:
        description:
            - Configure global range attributes.
        default: null
        type: dict
        suboptions:
            admin_concurrent:
                description:
                    - Enable/disable concurrent login of adminstrative users.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_https_pki_required:
                description:
                    - Enable/disable HTTPS login page when PKI is enabled.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_https_ssl_versions:
                description:
                    - Allowed SSL/TLS versions for web administration.
                type: str
                choices:
                    - 'tlsv1-0'
                    - 'tlsv1-1'
                    - 'tlsv1-2'
                    - 'tlsv1-3'
            admin_lockout_duration:
                description:
                    - Lockout duration for FortiSwitch administration (1 - 2147483647 sec).
                type: int
            admin_lockout_threshold:
                description:
                    - Lockout threshold for FortiSwitch administration.
                type: int
            admin_password_hash:
                description:
                    - Admin password hash algorithm. (sha1, sha256, pbkdf2)
                type: str
                choices:
                    - 'sha1'
                    - 'sha256'
                    - 'pbkdf2'
                    - 'pbkdf2-high'
            admin_port:
                description:
                    - Administrative access HTTP port (1 - 65535).
                type: int
            admin_scp:
                description:
                    - Enable/disable downloading of system configuraiton using SCP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_server_cert:
                description:
                    - Administrative HTTPS server certificate.
                type: str
            admin_sport:
                description:
                    - Administrative access HTTPS port (1 - 65535).
                type: int
            admin_ssh_grace_time:
                description:
                    - Administrative access login grace time (10 - 3600 sec).
                type: int
            admin_ssh_port:
                description:
                    - Administrative access SSH port (1 - 65535).
                type: int
            admin_ssh_v1:
                description:
                    - Enable/disable SSH v1 compatibility.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_telnet_port:
                description:
                    - Administrative access TELNET port (1 - 65535).
                type: int
            admintimeout:
                description:
                    - Idle time-out for firewall administration.
                type: int
            alert_interval:
                description:
                    - Interval between each syslog entry when a sensor is out-of-range with respect to its threshold (in mins).
                type: int
            alertd_relog:
                description:
                    - Enable/disable re-logs when a sensor exceeds it"s threshold.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            allow_subnet_overlap:
                description:
                    - Enable/disable subnet overlap.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            arp_timeout:
                description:
                    - ARP timeout value in seconds.
                type: int
            asset_tag:
                description:
                    - Asset tag.
                type: str
            auto_isl:
                description:
                    - Enable/disable automatic inter-switch LAG.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ca_certificate_802dot1x:
                description:
                    - CA certificate for Port Security (802.1x).
                type: str
            certificate_802dot1x:
                description:
                    - Certificate for Port Security (802.1x).
                type: str
            cfg_revert_timeout:
                description:
                    - Time-out for reverting to the last saved configuration (10 - 2147483647).
                type: int
            cfg_save:
                description:
                    - Configure configuration saving mode (valid only for changes made in the CLI).
                type: str
                choices:
                    - 'automatic'
                    - 'manual'
                    - 'revert'
            clt_cert_req:
                description:
                    - Enable the requirement of client certificate for GUI login.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            csr_ca_attribute:
                description:
                    - Enable/disable CA attribute in CSR.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            daily_restart:
                description:
                    - Enable/disable FortiSwitch daily reboot.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            delaycli_timeout_cleanup:
                description:
                    - Time-out for cleaning up the delay cli execution completion data (1-1440 minutes).
                type: int
            detect_ip_conflict:
                description:
                    - Enable/disable detection of IP address conflicts.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dh_params:
                description:
                    - Minimum size of Diffie-Hellman prime for HTTPS/SSH (bits).
                type: int
            dhcp_circuit_id:
                description:
                    - List the parameters to be included to inform about client identification.
                type: str
                choices:
                    - 'intfname'
                    - 'vlan'
                    - 'hostname'
                    - 'mode'
                    - 'description'
            dhcp_client_location:
                description:
                    - List the parameters to be included to inform about client location.
                type: str
                choices:
                    - 'intfname'
                    - 'vlan'
                    - 'hostname'
                    - 'mode'
                    - 'description'
            dhcp_option_format:
                description:
                    - DHCP Option format string.
                type: str
                choices:
                    - 'legacy'
                    - 'ascii'
            dhcp_remote_id:
                description:
                    - List the parameters to be included in remote-id field.
                type: str
                choices:
                    - 'mac'
                    - 'hostname'
                    - 'ip'
            dhcp_server_access_list:
                description:
                    - Enable/Disable trusted DHCP Server list.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp_snoop_client_req:
                description:
                    - Client DHCP packet broadcast mode.
                type: str
                choices:
                    - 'forward-untrusted'
                    - 'drop-untrusted'
            dhcps_db_exp:
                description:
                    - Expiry time for dhcp-snoop server-db entry (300-259200 sec).
                type: int
            dhcps_db_per_port_learn_limit:
                description:
                    - Per Interface dhcp-server entries learn limit .
                type: int
            dst:
                description:
                    - Enable/disable daylight saving time.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            failtime:
                description:
                    - Fail-time for PING server lost.
                type: int
            fortilink_auto_discovery:
                description:
                    - Enable/disable automatic discovery of FortiLink.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            hostname:
                description:
                    - FortiSwitch hostname.
                type: str
            image_rotation:
                description:
                    - Enable/disable image upgrade partition rotation.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            interval:
                description:
                    - Dead gateway detection interval.
                type: int
            ip_conflict_ignore_default:
                description:
                    - Enable/disable IP conflict detection for default IP address.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_accept_dad:
                description:
                    - Whether to accept ipv6 DAD (Duplicate Address Detection).
                type: int
            ipv6_all_forwarding:
                description:
                    - Enable/disable ipv6 all forwarding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            kernel_crashlog:
                description:
                    - Enable/disable capture of kernel error messages to crash log.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            kernel_devicelog:
                description:
                    - Enable/disable capture of kernel device messages to log.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            l3_host_expiry:
                description:
                    - Enable/disable l3 host expiry.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            language:
                description:
                    - GUI display language.
                type: str
                choices:
                    - 'browser'
                    - 'english'
                    - 'simch'
                    - 'japanese'
                    - 'korean'
                    - 'spanish'
                    - 'trach'
                    - 'french'
                    - 'portuguese'
                    - 'german'
            ldapconntimeout:
                description:
                    - LDAP connection time-out (0 - 2147483647 milliseconds).
                type: int
            post_login_banner:
                description:
                    - System post-login banner message.
                type: str
            pre_login_banner:
                description:
                    - System pre-login banner message.
                type: str
            private_data_encryption:
                description:
                    - Enable/disable private data encryption using an AES 128-bit key.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            radius_coa_port:
                description:
                    - RADIUS CoA port number.
                type: int
            radius_port:
                description:
                    - RADIUS server port number.
                type: int
            remoteauthtimeout:
                description:
                    - Remote authentication (RADIUS/LDAP) time-out (0 - 300).
                type: int
            restart_time:
                description:
                    - 'Daily restart time <hh:mm>.'
                type: str
            revision_backup_on_logout:
                description:
                    - Enable/disable automatic revision backup upon logout.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            revision_backup_on_upgrade:
                description:
                    - Enable/disable automatic revision backup upon upgrade of system image.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strong_crypto:
                description:
                    - Enable/disable strong cryptography for HTTPS/SSH access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_mgmt_mode:
                description:
                    - Switch mode setting.
                type: str
                choices:
                    - 'local'
                    - 'fortilink'
            tcp6_mss_min:
                description:
                    - Minimum allowed TCP MSS value in bytes.
                type: int
            tcp_mss_min:
                description:
                    - Minimum allowed TCP MSS value in bytes.
                type: int
            tcp_options:
                description:
                    - Enable/disable TCP options (timestamps, SACK, window scaling).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tftp:
                description:
                    - Enable/disable TFTP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            timezone:
                description:
                    - Time zone.
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
'''

EXAMPLES = '''
- name: Configure global range attributes.
  fortinet.fortiswitch.fortiswitch_system_global:
      system_global:
          802.1x_ca_certificate: "<your_own_value>"
          802.1x_certificate: "<your_own_value>"
          admin_concurrent: "enable"
          admin_https_pki_required: "enable"
          admin_https_ssl_versions: "tlsv1-0"
          admin_lockout_duration: "8"
          admin_lockout_threshold: "9"
          admin_password_hash: "sha1"
          admin_port: "11"
          admin_scp: "enable"
          admin_server_cert: "<your_own_value>"
          admin_sport: "14"
          admin_ssh_grace_time: "15"
          admin_ssh_port: "16"
          admin_ssh_v1: "enable"
          admin_telnet_port: "18"
          admintimeout: "19"
          alert_interval: "20"
          alertd_relog: "enable"
          allow_subnet_overlap: "enable"
          arp_timeout: "23"
          asset_tag: "<your_own_value>"
          auto_isl: "enable"
          cfg_revert_timeout: "26"
          cfg_save: "automatic"
          clt_cert_req: "enable"
          csr_ca_attribute: "enable"
          daily_restart: "enable"
          delaycli_timeout_cleanup: "31"
          detect_ip_conflict: "enable"
          dh_params: "33"
          dhcp_circuit_id: "intfname"
          dhcp_client_location: "intfname"
          dhcp_option_format: "legacy"
          dhcp_remote_id: "mac"
          dhcp_server_access_list: "enable"
          dhcp_snoop_client_req: "forward-untrusted"
          dhcps_db_exp: "40"
          dhcps_db_per_port_learn_limit: "41"
          dst: "enable"
          failtime: "43"
          fortilink_auto_discovery: "enable"
          hostname: "myhostname"
          image_rotation: "disable"
          interval: "47"
          ip_conflict_ignore_default: "enable"
          ipv6_accept_dad: "49"
          ipv6_all_forwarding: "enable"
          kernel_crashlog: "enable"
          kernel_devicelog: "enable"
          l3_host_expiry: "enable"
          language: "browser"
          ldapconntimeout: "55"
          post_login_banner: "<your_own_value>"
          pre_login_banner: "<your_own_value>"
          private_data_encryption: "disable"
          radius_coa_port: "59"
          radius_port: "60"
          remoteauthtimeout: "61"
          restart_time: "<your_own_value>"
          revision_backup_on_logout: "enable"
          revision_backup_on_upgrade: "enable"
          strong_crypto: "enable"
          switch_mgmt_mode: "local"
          tcp6_mss_min: "67"
          tcp_mss_min: "68"
          tcp_options: "enable"
          tftp: "enable"
          timezone: "01"
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


def filter_system_global_data(json):
    option_list = ['802.1x_ca_certificate', '802.1x_certificate', 'admin_concurrent',
                   'admin_https_pki_required', 'admin_https_ssl_versions', 'admin_lockout_duration',
                   'admin_lockout_threshold', 'admin_password_hash', 'admin_port',
                   'admin_scp', 'admin_server_cert', 'admin_sport',
                   'admin_ssh_grace_time', 'admin_ssh_port', 'admin_ssh_v1',
                   'admin_telnet_port', 'admintimeout', 'alert_interval',
                   'alertd_relog', 'allow_subnet_overlap', 'arp_timeout',
                   'asset_tag', 'auto_isl', 'cfg_revert_timeout',
                   'cfg_save', 'clt_cert_req', 'csr_ca_attribute',
                   'daily_restart', 'delaycli_timeout_cleanup', 'detect_ip_conflict',
                   'dh_params', 'dhcp_circuit_id', 'dhcp_client_location',
                   'dhcp_option_format', 'dhcp_remote_id', 'dhcp_server_access_list',
                   'dhcp_snoop_client_req', 'dhcps_db_exp', 'dhcps_db_per_port_learn_limit',
                   'dst', 'failtime', 'fortilink_auto_discovery',
                   'hostname', 'image_rotation', 'interval',
                   'ip_conflict_ignore_default', 'ipv6_accept_dad', 'ipv6_all_forwarding',
                   'kernel_crashlog', 'kernel_devicelog', 'l3_host_expiry',
                   'language', 'ldapconntimeout', 'post_login_banner',
                   'pre_login_banner', 'private_data_encryption', 'radius_coa_port',
                   'radius_port', 'remoteauthtimeout', 'restart_time',
                   'revision_backup_on_logout', 'revision_backup_on_upgrade', 'strong_crypto',
                   'switch_mgmt_mode', 'tcp6_mss_min', 'tcp_mss_min',
                   'tcp_options', 'tftp', 'timezone']

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


def system_global(data, fos):
    system_global_data = data['system_global']
    filtered_data = underscore_to_hyphen(filter_system_global_data(system_global_data))

    return fos.set('system',
                   'global',
                   data=filtered_data,
                   )


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def fortiswitch_system(data, fos):
    fos.do_member_operation('system', 'global')
    current_cmdb_index = fos.monitor_get('/system/status')['cmdb-index']
    if data['system_global']:
        resp = system_global(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_global'))

    return not is_successful_status(resp), \
        is_successful_status(resp) and \
        current_cmdb_index != resp['cmdb-index'], \
        resp, {}


versioned_schema = {
    "v_range": [
        [
            "v7.0.0",
            ""
        ]
    ],
    "type": "dict",
    "children": {
        "certificate_802dot1x": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "802.1x-certificate",
            "help": "Certificate for Port Security (802.1x).",
            "category": "unitary"
        },
        "ipv6_all_forwarding": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "ipv6-all-forwarding",
            "help": "Enable/disable ipv6 all forwarding.",
            "category": "unitary"
        },
        "dhcps_db_per_port_learn_limit": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "dhcps-db-per-port-learn-limit",
            "help": "Per Interface dhcp-server entries learn limit .",
            "category": "unitary"
        },
        "private_data_encryption": {
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
            "name": "private-data-encryption",
            "help": "Enable/disable private data encryption using an AES 128-bit key.",
            "category": "unitary"
        },
        "remoteauthtimeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "remoteauthtimeout",
            "help": "Remote authentication (RADIUS/LDAP) time-out (0 - 300).",
            "category": "unitary"
        },
        "alert_interval": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "alert-interval",
            "help": "Interval between each syslog entry when a sensor is out-of-range with respect to its threshold (in mins).",
            "category": "unitary"
        },
        "pre_login_banner": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "pre-login-banner",
            "help": "System pre-login banner message.",
            "category": "unitary"
        },
        "switch_mgmt_mode": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "local"
                },
                {
                    "value": "fortilink"
                }
            ],
            "name": "switch-mgmt-mode",
            "help": "Switch mode setting.",
            "category": "unitary"
        },
        "strong_crypto": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "strong-crypto",
            "help": "Enable/disable strong cryptography for HTTPS/SSH access.",
            "category": "unitary"
        },
        "detect_ip_conflict": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "detect-ip-conflict",
            "help": "Enable/disable detection of IP address conflicts.",
            "category": "unitary"
        },
        "asset_tag": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "asset-tag",
            "help": "Asset tag.",
            "category": "unitary"
        },
        "ip_conflict_ignore_default": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "ip-conflict-ignore-default",
            "help": "Enable/disable IP conflict detection for default IP address.",
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
            "help": "Time zone.",
            "category": "unitary"
        },
        "admin_sport": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "integer",
            "name": "admin-sport",
            "help": "Administrative access HTTPS port (1 - 65535).",
            "category": "unitary"
        },
        "image_rotation": {
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
            "name": "image-rotation",
            "help": "Enable/disable image upgrade partition rotation.",
            "category": "unitary"
        },
        "admin_telnet_port": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "admin-telnet-port",
            "help": "Administrative access TELNET port (1 - 65535).",
            "category": "unitary"
        },
        "kernel_crashlog": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "kernel-crashlog",
            "help": "Enable/disable capture of kernel error messages to crash log.",
            "category": "unitary"
        },
        "fortilink_auto_discovery": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.2.4"
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "fortilink-auto-discovery",
            "help": "Enable/disable automatic discovery of FortiLink.",
            "category": "unitary"
        },
        "kernel_devicelog": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "kernel-devicelog",
            "help": "Enable/disable capture of kernel device messages to log.",
            "category": "unitary"
        },
        "revision_backup_on_upgrade": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "revision-backup-on-upgrade",
            "help": "Enable/disable automatic revision backup upon upgrade of system image.",
            "category": "unitary"
        },
        "admin_https_ssl_versions": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "tlsv1-0"
                },
                {
                    "value": "tlsv1-1"
                },
                {
                    "value": "tlsv1-2"
                },
                {
                    "value": "tlsv1-3"
                }
            ],
            "name": "admin-https-ssl-versions",
            "help": "Allowed SSL/TLS versions for web administration.",
            "category": "unitary"
        },
        "hostname": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "hostname",
            "help": "FortiSwitch hostname.",
            "category": "unitary"
        },
        "revision_backup_on_logout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "revision-backup-on-logout",
            "help": "Enable/disable automatic revision backup upon logout.",
            "category": "unitary"
        },
        "tcp6_mss_min": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "tcp6-mss-min",
            "help": "Minimum allowed TCP MSS value in bytes.",
            "category": "unitary"
        },
        "cfg_revert_timeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "cfg-revert-timeout",
            "help": "Time-out for reverting to the last saved configuration (10 - 2147483647).",
            "category": "unitary"
        },
        "admin_ssh_v1": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "admin-ssh-v1",
            "help": "Enable/disable SSH v1 compatibility.",
            "category": "unitary"
        },
        "allow_subnet_overlap": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "allow-subnet-overlap",
            "help": "Enable/disable subnet overlap.",
            "category": "unitary"
        },
        "dh_params": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "dh-params",
            "help": "Minimum size of Diffie-Hellman prime for HTTPS/SSH (bits).",
            "category": "unitary"
        },
        "ldapconntimeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "ldapconntimeout",
            "help": "LDAP connection time-out (0 - 2147483647 milliseconds).",
            "category": "unitary"
        },
        "tcp_mss_min": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "tcp-mss-min",
            "help": "Minimum allowed TCP MSS value in bytes.",
            "category": "unitary"
        },
        "admin_concurrent": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "admin-concurrent",
            "help": "Enable/disable concurrent login of adminstrative users.",
            "category": "unitary"
        },
        "admintimeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "admintimeout",
            "help": "Idle time-out for firewall administration.",
            "category": "unitary"
        },
        "arp_timeout": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "arp-timeout",
            "help": "ARP timeout value in seconds.",
            "category": "unitary"
        },
        "admin_lockout_duration": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "admin-lockout-duration",
            "help": "Lockout duration for FortiSwitch administration (1 - 2147483647 sec).",
            "category": "unitary"
        },
        "dhcp_server_access_list": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "dhcp-server-access-list",
            "help": "Enable/Disable trusted DHCP Server list.",
            "category": "unitary"
        },
        "admin_port": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "integer",
            "name": "admin-port",
            "help": "Administrative access HTTP port (1 - 65535).",
            "category": "unitary"
        },
        "l3_host_expiry": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "l3-host-expiry",
            "help": "Enable/disable l3 host expiry.",
            "category": "unitary"
        },
        "post_login_banner": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "post-login-banner",
            "help": "System post-login banner message.",
            "category": "unitary"
        },
        "failtime": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "failtime",
            "help": "Fail-time for PING server lost.",
            "category": "unitary"
        },
        "admin_lockout_threshold": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "admin-lockout-threshold",
            "help": "Lockout threshold for FortiSwitch administration.",
            "category": "unitary"
        },
        "dhcps_db_exp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "dhcps-db-exp",
            "help": "Expiry time for dhcp-snoop server-db entry (300-259200 sec,).",
            "category": "unitary"
        },
        "ca_certificate_802dot1x": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "802.1x-ca-certificate",
            "help": "CA certificate for Port Security (802.1x).",
            "category": "unitary"
        },
        "dhcp_remote_id": {
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
                    "value": "hostname"
                },
                {
                    "value": "ip"
                }
            ],
            "name": "dhcp-remote-id",
            "help": "List the parameters to be included in remote-id field.",
            "category": "unitary"
        },
        "dhcp_snoop_client_req": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "forward-untrusted"
                },
                {
                    "value": "drop-untrusted"
                }
            ],
            "name": "dhcp-snoop-client-req",
            "help": "Client DHCP packet broadcast mode.",
            "category": "unitary"
        },
        "dhcp_client_location": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.2.1"
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "intfname"
                },
                {
                    "value": "vlan"
                },
                {
                    "value": "hostname"
                },
                {
                    "value": "mode"
                },
                {
                    "value": "description"
                }
            ],
            "name": "dhcp-client-location",
            "help": "List the parameters to be included to inform about client location.",
            "category": "unitary"
        },
        "csr_ca_attribute": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "csr-ca-attribute",
            "help": "Enable/disable CA attribute in CSR.",
            "category": "unitary"
        },
        "ipv6_accept_dad": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "ipv6-accept-dad",
            "help": "Whether to accept ipv6 DAD (Duplicate Address Detection).",
            "category": "unitary"
        },
        "admin_ssh_port": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "admin-ssh-port",
            "help": "Administrative access SSH port (1 - 65535).",
            "category": "unitary"
        },
        "admin_server_cert": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "string",
            "name": "admin-server-cert",
            "help": "Administrative HTTPS server certificate.",
            "category": "unitary"
        },
        "auto_isl": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.2.4"
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "auto-isl",
            "help": "Enable/disable automatic inter-switch LAG.",
            "category": "unitary"
        },
        "language": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "browser"
                },
                {
                    "value": "english"
                },
                {
                    "value": "simch"
                },
                {
                    "value": "japanese"
                },
                {
                    "value": "korean"
                },
                {
                    "value": "spanish"
                },
                {
                    "value": "trach"
                },
                {
                    "value": "french"
                },
                {
                    "value": "portuguese"
                },
                {
                    "value": "german"
                }
            ],
            "name": "language",
            "help": "GUI display language.",
            "category": "unitary"
        },
        "radius_coa_port": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "radius-coa-port",
            "help": "RADIUS CoA port number.",
            "category": "unitary"
        },
        "dst": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "dst",
            "help": "Enable/disable daylight saving time.",
            "category": "unitary"
        },
        "interval": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "interval",
            "help": "Dead gateway detection interval.",
            "category": "unitary"
        },
        "cfg_save": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "automatic"
                },
                {
                    "value": "manual"
                },
                {
                    "value": "revert"
                }
            ],
            "name": "cfg-save",
            "help": "Configure configuration saving mode (valid only for changes made in the CLI).",
            "category": "unitary"
        },
        "restart_time": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "name": "restart-time",
            "help": "Daily restart time <hh:mm>.",
            "category": "unitary"
        },
        "dhcp_option_format": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "legacy"
                },
                {
                    "value": "ascii"
                }
            ],
            "name": "dhcp-option-format",
            "help": "DHCP Option format string.",
            "category": "unitary"
        },
        "admin_scp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "admin-scp",
            "help": "Enable/disable downloading of system configuraiton using SCP.",
            "category": "unitary"
        },
        "alertd_relog": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "alertd-relog",
            "help": "Enable/disable re-logs when a sensor exceeds it's threshold.",
            "category": "unitary"
        },
        "clt_cert_req": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "clt-cert-req",
            "help": "Enable the requirement of client certificate for GUI login.",
            "category": "unitary"
        },
        "daily_restart": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "daily-restart",
            "help": "Enable/disable FortiSwitch daily reboot.",
            "category": "unitary"
        },
        "tftp": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "tftp",
            "help": "Enable/disable TFTP.",
            "category": "unitary"
        },
        "admin_ssh_grace_time": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "admin-ssh-grace-time",
            "help": "Administrative access login grace time (10 - 3600 sec).",
            "category": "unitary"
        },
        "admin_https_pki_required": {
            "v_range": [
                [
                    "v7.0.0",
                    "v7.0.6"
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "admin-https-pki-required",
            "help": "Enable/disable HTTPS login page when PKI is enabled.",
            "category": "unitary"
        },
        "radius_port": {
            "v_range": [
                [
                    "v7.0.0",
                    ""
                ]
            ],
            "type": "integer",
            "name": "radius-port",
            "help": "RADIUS server port number.",
            "category": "unitary"
        },
        "dhcp_circuit_id": {
            "v_range": [
                [
                    "v7.2.2",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "intfname"
                },
                {
                    "value": "vlan"
                },
                {
                    "value": "hostname"
                },
                {
                    "value": "mode"
                },
                {
                    "value": "description"
                }
            ],
            "name": "dhcp-circuit-id",
            "help": "List the parameters to be included to inform about client identification.",
            "category": "unitary"
        },
        "admin_password_hash": {
            "v_range": [
                [
                    "v7.4.0",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "sha1"
                },
                {
                    "value": "sha256"
                },
                {
                    "value": "pbkdf2"
                },
                {
                    "value": "pbkdf2-high"
                }
            ],
            "name": "admin-password-hash",
            "help": "Admin password hash algorithm. (sha1,sha256,pbkdf2)",
            "category": "unitary"
        },
        "tcp_options": {
            "v_range": [
                [
                    "v7.4.1",
                    ""
                ]
            ],
            "type": "string",
            "options": [
                {
                    "value": "enable"
                },
                {
                    "value": "disable"
                }
            ],
            "name": "tcp-options",
            "help": "Enable/disable TCP options (timestamps,SACK,window scaling).",
            "category": "unitary"
        },
        "delaycli_timeout_cleanup": {
            "v_range": [
                [
                    "v7.4.1",
                    ""
                ]
            ],
            "type": "integer",
            "name": "delaycli-timeout-cleanup",
            "help": "Time-out for cleaning up the delay cli execution completion data (1-1440 minutes,).",
            "category": "unitary"
        }
    },
    "name": "global",
    "help": "Configure global range attributes.",
    "category": "complex"
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
        "system_global": {
            "required": False, "type": "dict", "default": None,
            "options": {}
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_global"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_global"]['options'][attribute_name]['required'] = True

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_global")
        is_error, has_changed, result, diff = fortiswitch_system(module.params, fos)
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
