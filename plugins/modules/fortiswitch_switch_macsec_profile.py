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
module: fortiswitch_switch_macsec_profile
short_description: MACsec configuration profiles in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify switch_macsec feature and profile category.
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
    switch_macsec_profile:
        description:
            - MACsec configuration profiles.
        default: null
        type: dict
        suboptions:
            cipher_suite:
                description:
                    - MACsec cipher suite.
                type: str
                choices:
                    - 'GCM-AES-128'
            confident_offset:
                description:
                    - Choose different confident offset bytes.
                type: str
                choices:
                    - '0'
                    - '30'
                    - '50'
            eap_tls_ca_cert:
                description:
                    - CA certificate for MACSEC CAK EAP-TLS.
                type: str
            eap_tls_cert:
                description:
                    - Client certificate for MACSEC CAK EAP-TLS.
                type: str
            eap_tls_identity:
                description:
                    - Client identity for MACSEC CAK EAP-TLS.
                type: str
            eap_tls_radius_server:
                description:
                    - Radius Server for MACSEC CAK EAP-TLS.
                type: str
            encrypt_traffic:
                description:
                    - Enable/disable Encryption of MACsec traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            include_macsec_sci:
                description:
                    - Include MACsec TX SCI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            include_mka_icv_ind:
                description:
                    - Include MKA ICV indicator.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            macsec_mode:
                description:
                    - Set mode of the MACsec Profile.
                type: str
                choices:
                    - 'static-cak'
                    - 'dynamic-cak'
                    - 'fortilink'
            macsec_validate:
                description:
                    - Choose different MACsec validate mode.
                type: str
                choices:
                    - 'strict'
            mka_priority:
                description:
                    - MACsec MKA priority.
                type: int
            mka_psk:
                description:
                    - MACsec MKA pre-shared key configuration.
                type: list
                elements: dict
                suboptions:
                    crypto_alg:
                        description:
                            - PSK crypto algorithm.
                        type: str
                        choices:
                            - 'AES_128_CMAC'
                            - 'AES_256_CMAC'
                    mka_cak:
                        description:
                            - MKA CAK pre-shared key hex string.
                        type: str
                    mka_ckn:
                        description:
                            - MKA CKN pre-shared key hex string.
                        type: str
                    name:
                        description:
                            - pre-shared-key name.
                        type: str
                    status:
                        description:
                            - Status of this PSK.
                        type: str
                        choices:
                            - 'active'
            mka_sak_rekey_time:
                description:
                    - MACsec MKA Session SAK rekey timer.
                type: int
            name:
                description:
                    - Profile name.
                required: true
                type: str
            replay_protect:
                description:
                    - Enable/disable MACsec replay protection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            replay_window:
                description:
                    - MACsec replay window size.
                type: int
            status:
                description:
                    - Enable/disable this Profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            traffic_policy:
                description:
                    - MACsec traffic policy configuration.
                type: list
                elements: dict
                suboptions:
                    exclude_protocol:
                        description:
                            - Exclude protocols that should not be MACsec-secured.
                        type: str
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                            - 'dot1q'
                            - 'qinq'
                            - 'fortilink'
                            - 'arp'
                            - 'stp'
                            - 'lldp'
                            - 'lacp'
                    name:
                        description:
                            - Traffic policy type name.
                        type: str
                    security_policy:
                        description:
                            - Must/Should secure the traffic.
                        type: str
                        choices:
                            - 'must-secure'
                    status:
                        description:
                            - Enable/disable this Traffic policy.
                        type: str
                        choices:
                            - 'enable'
"""

EXAMPLES = """
- name: MACsec configuration profiles.
  fortinet.fortiswitch.fortiswitch_switch_macsec_profile:
      state: "present"
      switch_macsec_profile:
          cipher_suite: "GCM-AES-128"
          confident_offset: "0"
          eap_tls_ca_cert: "<your_own_value>"
          eap_tls_cert: "<your_own_value>"
          eap_tls_identity: "<your_own_value>"
          eap_tls_radius_server: "<your_own_value>"
          encrypt_traffic: "enable"
          include_macsec_sci: "enable"
          include_mka_icv_ind: "enable"
          macsec_mode: "static-cak"
          macsec_validate: "strict"
          mka_priority: "127"
          mka_psk:
              -
                  crypto_alg: "AES_128_CMAC"
                  mka_cak: "<your_own_value>"
                  mka_ckn: "<your_own_value>"
                  name: "default_name_19"
                  status: "active"
          mka_sak_rekey_time: "500000"
          name: "default_name_22"
          replay_protect: "enable"
          replay_window: "8388607"
          status: "enable"
          traffic_policy:
              -
                  exclude_protocol: "ipv4"
                  name: "default_name_28"
                  security_policy: "must-secure"
                  status: "enable"
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


def filter_switch_macsec_profile_data(json):
    option_list = [
        "cipher_suite",
        "confident_offset",
        "eap_tls_ca_cert",
        "eap_tls_cert",
        "eap_tls_identity",
        "eap_tls_radius_server",
        "encrypt_traffic",
        "include_macsec_sci",
        "include_mka_icv_ind",
        "macsec_mode",
        "macsec_validate",
        "mka_priority",
        "mka_psk",
        "mka_sak_rekey_time",
        "name",
        "replay_protect",
        "replay_window",
        "status",
        "traffic_policy",
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


def switch_macsec_profile(data, fos, check_mode=False):
    state = data.get("state", None)

    switch_macsec_profile_data = data["switch_macsec_profile"]

    filtered_data = filter_switch_macsec_profile_data(switch_macsec_profile_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("switch.macsec", "profile", filtered_data)
        current_data = fos.get("switch.macsec", "profile", mkey=mkey)
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
            "switch.macsec",
            "profile",
            data=filtered_data,
        )

    elif state == "absent":
        return fos.delete("switch.macsec", "profile", mkey=filtered_data["name"])
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


def fortiswitch_switch_macsec(data, fos, check_mode):
    fos.do_member_operation("switch.macsec", "profile")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["switch_macsec_profile"]:
        resp = switch_macsec_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("switch_macsec_profile"))
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
        "status": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "status",
            "help": "Enable/disable this Profile.",
            "category": "unitary",
        },
        "replay_protect": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "replay-protect",
            "help": "Enable/disable MACsec replay protection.",
            "category": "unitary",
        },
        "replay_window": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "replay-window",
            "help": "MACsec replay window size.",
            "category": "unitary",
        },
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "Profile name.",
            "category": "unitary",
        },
        "macsec_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "static-cak"},
                {"value": "dynamic-cak", "v_range": [["v7.2.1", ""]]},
                {"value": "fortilink", "v_range": [["v7.4.0", ""]]},
            ],
            "name": "macsec-mode",
            "help": "Set mode of the MACsec Profile.",
            "category": "unitary",
        },
        "include_mka_icv_ind": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable", "v_range": []}],
            "name": "include-mka-icv-ind",
            "help": "Include MKA ICV indicator.",
            "category": "unitary",
        },
        "traffic_policy": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}],
                    "name": "status",
                    "help": "Enable/disable this Traffic policy.",
                    "category": "unitary",
                },
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Traffic policy type name.",
                    "category": "unitary",
                },
                "security_policy": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "must-secure"}],
                    "name": "security-policy",
                    "help": "Must/Should secure the traffic.",
                    "category": "unitary",
                },
                "exclude_protocol": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ipv4"},
                        {"value": "ipv6"},
                        {"value": "dot1q"},
                        {"value": "qinq"},
                        {"value": "fortilink"},
                        {"value": "arp"},
                        {"value": "stp"},
                        {"value": "lldp"},
                        {"value": "lacp"},
                    ],
                    "name": "exclude-protocol",
                    "help": "Exclude protocols that should not be MACsec-secured.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "traffic-policy",
            "help": "MACsec traffic policy configuration.",
            "mkey": "name",
            "category": "table",
        },
        "cipher_suite": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "GCM-AES-128"}],
            "name": "cipher-suite",
            "help": "MACsec cipher suite.",
            "category": "unitary",
        },
        "macsec_validate": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "strict"}],
            "name": "macsec-validate",
            "help": "Choose different MACsec validate mode.",
            "category": "unitary",
        },
        "mka_priority": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
            "name": "mka-priority",
            "help": "MACsec MKA priority.",
            "category": "unitary",
        },
        "encrypt_traffic": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "encrypt-traffic",
            "help": "Enable/disable Encryption of MACsec traffic.",
            "category": "unitary",
        },
        "mka_psk": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "active"}],
                    "name": "status",
                    "help": "Status of this PSK.",
                    "category": "unitary",
                },
                "crypto_alg": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "AES_128_CMAC"},
                        {"value": "AES_256_CMAC", "v_range": []},
                    ],
                    "name": "crypto-alg",
                    "help": "PSK crypto algorithm.",
                    "category": "unitary",
                },
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "pre-shared-key name.",
                    "category": "unitary",
                },
                "mka_cak": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "mka-cak",
                    "help": "MKA CAK pre-shared key hex string.",
                    "category": "unitary",
                },
                "mka_ckn": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "mka-ckn",
                    "help": "MKA CKN pre-shared key hex string.",
                    "category": "unitary",
                },
            },
            "v_range": [["v7.0.0", ""]],
            "name": "mka-psk",
            "help": "MACsec MKA pre-shared key configuration.",
            "mkey": "name",
            "category": "table",
        },
        "confident_offset": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "0"}, {"value": "30"}, {"value": "50"}],
            "name": "confident-offset",
            "help": "Choose different confident offset bytes.",
            "category": "unitary",
        },
        "include_macsec_sci": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
            "name": "include-macsec-sci",
            "help": "Include MACsec TX SCI.",
            "category": "unitary",
        },
        "eap_tls_ca_cert": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "name": "eap-tls-ca-cert",
            "help": "CA certificate for MACSEC CAK EAP-TLS.",
            "category": "unitary",
        },
        "eap_tls_cert": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "name": "eap-tls-cert",
            "help": "Client certificate for MACSEC CAK EAP-TLS.",
            "category": "unitary",
        },
        "eap_tls_radius_server": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "name": "eap-tls-radius-server",
            "help": "Radius Server for MACSEC CAK EAP-TLS.",
            "category": "unitary",
        },
        "eap_tls_identity": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "name": "eap-tls-identity",
            "help": "Client identity for MACSEC CAK EAP-TLS.",
            "category": "unitary",
        },
        "mka_sak_rekey_time": {
            "v_range": [],
            "type": "integer",
            "name": "mka-sak-rekey-time",
            "help": "MACsec MKA Session SAK rekey timer.",
            "category": "unitary",
        },
    },
    "v_range": [["v7.0.0", ""]],
    "name": "profile",
    "help": "MACsec configuration profiles.",
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
        "switch_macsec_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_macsec_profile"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_macsec_profile"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "switch_macsec_profile"
        )
        is_error, has_changed, result, diff = fortiswitch_switch_macsec(
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
