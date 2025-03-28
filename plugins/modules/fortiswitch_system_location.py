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
module: fortiswitch_system_location
short_description: Configure Location table in Fortinet's FortiSwitch
description:
    - This module is able to configure a FortiSwitch device by allowing the
      user to set and modify system feature and location category.
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
    system_location:
        description:
            - Configure Location table.
        default: null
        type: dict
        suboptions:
            address_civic:
                description:
                    - Configure Location Civic Address.
                type: dict
                suboptions:
                    additional:
                        description:
                            - Additional location information.
                        type: str
                    additional_code:
                        description:
                            - Additional code.
                        type: str
                    block:
                        description:
                            - Neighborhood or block.
                        type: str
                    branch_road:
                        description:
                            - Branch road name.
                        type: str
                    building:
                        description:
                            - Building (structure).
                        type: str
                    city:
                        description:
                            - City, township, or shi (JP).
                        type: str
                    city_division:
                        description:
                            - City division, borough, city district, ward, or chou (JP).
                        type: str
                    country:
                        description:
                            - The two-letter ISO 3166 country code in capital ASCII letters eg. US, CA, DK, DE.
                        type: str
                    country_subdivision:
                        description:
                            - National subdivisions (state, canton, region, province, or prefecture).
                        type: str
                    county:
                        description:
                            - County, parish, gun (JP), or district (IN).
                        type: str
                    direction:
                        description:
                            - Leading street direction.
                        type: str
                    floor:
                        description:
                            - Floor.
                        type: str
                    landmark:
                        description:
                            - Landmark or vanity address.
                        type: str
                    language:
                        description:
                            - Language.
                        type: str
                    name:
                        description:
                            - Name (residence and office occupant).
                        type: str
                    number:
                        description:
                            - House number.
                        type: str
                    number_suffix:
                        description:
                            - House number suffix.
                        type: str
                    place_type:
                        description:
                            - Placetype.
                        type: str
                    post_office_box:
                        description:
                            - Post office box (P.O. box).
                        type: str
                    postal_community:
                        description:
                            - Postal community name.
                        type: str
                    primary_road:
                        description:
                            - Primary road name.
                        type: str
                    road_section:
                        description:
                            - Road section.
                        type: str
                    room:
                        description:
                            - Room number.
                        type: str
                    script:
                        description:
                            - Script used to present the address information.
                        type: str
                    seat:
                        description:
                            - Seat number.
                        type: str
                    street:
                        description:
                            - Street.
                        type: str
                    street_name_post_mod:
                        description:
                            - Street name post modifier.
                        type: str
                    street_name_pre_mod:
                        description:
                            - Street name pre modifier.
                        type: str
                    street_suffix:
                        description:
                            - Street suffix.
                        type: str
                    sub_branch_road:
                        description:
                            - Sub branch road name.
                        type: str
                    trailing_str_suffix:
                        description:
                            - Trailing street suffix.
                        type: str
                    unit:
                        description:
                            - Unit (apartment, suite).
                        type: str
                    zip:
                        description:
                            - Postal/zip code.
                        type: str
            coordinates:
                description:
                    - Configure Location GPS Coordinates.
                type: dict
                suboptions:
                    altitude:
                        description:
                            - +/- Floating point no. eg. 117.47.
                        type: str
                    altitude_unit:
                        description:
                            - m ( meters), f ( floors).
                        type: str
                        choices:
                            - 'm'
                            - 'f'
                    datum:
                        description:
                            - WGS84, NAD83, NAD83/MLLW .
                        type: str
                        choices:
                            - 'WGS84'
                            - 'NAD83'
                            - 'NAD83/MLLW'
                    latitude:
                        description:
                            - Floating point start with ( +/- )  or end with ( N or S ) eg. +/-16.67 or 16.67N.
                        type: str
                    longitude:
                        description:
                            - Floating point start with ( +/- )  or end with ( E or W ) eg. +/-26.789 or 26.789E.
                        type: str
            elin_number:
                description:
                    - Configure Location ELIN Number.
                type: dict
                suboptions:
                    elin_number:
                        description:
                            - Configure Elin Callback Number, 10 to 20 bytes numerial string.
                        type: str
            name:
                description:
                    - Unique Location Item Name.
                required: true
                type: str
"""

EXAMPLES = """
- name: Configure Location table.
  fortinet.fortiswitch.fortiswitch_system_location:
      state: "present"
      system_location:
          address_civic:
              additional: "<your_own_value>"
              additional_code: "<your_own_value>"
              block: "<your_own_value>"
              branch_road: "<your_own_value>"
              building: "<your_own_value>"
              city: "<your_own_value>"
              city_division: "<your_own_value>"
              country: "<your_own_value>"
              country_subdivision: "<your_own_value>"
              county: "<your_own_value>"
              direction: "<your_own_value>"
              floor: "<your_own_value>"
              landmark: "<your_own_value>"
              language: "<your_own_value>"
              name: "default_name_18"
              number: "<your_own_value>"
              number_suffix: "<your_own_value>"
              place_type: "<your_own_value>"
              post_office_box: "<your_own_value>"
              postal_community: "<your_own_value>"
              primary_road: "<your_own_value>"
              road_section: "<your_own_value>"
              room: "<your_own_value>"
              script: "<your_own_value>"
              seat: "<your_own_value>"
              street: "<your_own_value>"
              street_name_post_mod: "<your_own_value>"
              street_name_pre_mod: "<your_own_value>"
              street_suffix: "<your_own_value>"
              sub_branch_road: "<your_own_value>"
              trailing_str_suffix: "<your_own_value>"
              unit: "<your_own_value>"
              zip: "<your_own_value>"
          coordinates:
              altitude: "<your_own_value>"
              altitude_unit: "m"
              datum: "WGS84"
              latitude: "<your_own_value>"
              longitude: "<your_own_value>"
          elin_number:
              elin_number: "<your_own_value>"
          name: "default_name_45"
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


def filter_system_location_data(json):
    option_list = ["address_civic", "coordinates", "elin_number", "name"]

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


def system_location(data, fos, check_mode=False):
    state = data.get("state", None)

    system_location_data = data["system_location"]

    filtered_data = filter_system_location_data(system_location_data)
    filtered_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system", "location", filtered_data)
        current_data = fos.get("system", "location", mkey=mkey)
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
            "system",
            "location",
            data=filtered_data,
        )

    elif state == "absent":
        return fos.delete("system", "location", mkey=filtered_data["name"])
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


def fortiswitch_system(data, fos, check_mode):
    fos.do_member_operation("system", "location")
    current_cmdb_index = fos.monitor_get("/system/status")["cmdb-index"]
    if data["system_location"]:
        resp = system_location(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_location"))
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
        "address_civic": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "country_subdivision": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "country-subdivision",
                    "help": "National subdivisions (state,canton,region,province,or prefecture).",
                    "category": "unitary",
                },
                "sub_branch_road": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "sub-branch-road",
                    "help": "Sub branch road name.",
                    "category": "unitary",
                },
                "street_name_pre_mod": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "street-name-pre-mod",
                    "help": "Street name pre modifier.",
                    "category": "unitary",
                },
                "number": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "number",
                    "help": "House number.",
                    "category": "unitary",
                },
                "seat": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "seat",
                    "help": "Seat number.",
                    "category": "unitary",
                },
                "county": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "county",
                    "help": "County,parish,gun (JP),or district (IN).",
                    "category": "unitary",
                },
                "street": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "street",
                    "help": "Street.",
                    "category": "unitary",
                },
                "unit": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "unit",
                    "help": "Unit (apartment,suite).",
                    "category": "unitary",
                },
                "city": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "city",
                    "help": "City,township,or shi (JP).",
                    "category": "unitary",
                },
                "additional": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "additional",
                    "help": "Additional location information.",
                    "category": "unitary",
                },
                "zip": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "zip",
                    "help": "Postal/zip code.",
                    "category": "unitary",
                },
                "floor": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "floor",
                    "help": "Floor.",
                    "category": "unitary",
                },
                "branch_road": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "branch-road",
                    "help": "Branch road name.",
                    "category": "unitary",
                },
                "street_name_post_mod": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "street-name-post-mod",
                    "help": "Street name post modifier.",
                    "category": "unitary",
                },
                "post_office_box": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "post-office-box",
                    "help": "Post office box (P.O. box).",
                    "category": "unitary",
                },
                "primary_road": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "primary-road",
                    "help": "Primary road name.",
                    "category": "unitary",
                },
                "place_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "place-type",
                    "help": "Placetype.",
                    "category": "unitary",
                },
                "direction": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "direction",
                    "help": "Leading street direction.",
                    "category": "unitary",
                },
                "street_suffix": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "street-suffix",
                    "help": "Street suffix.",
                    "category": "unitary",
                },
                "road_section": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "road-section",
                    "help": "Road section.",
                    "category": "unitary",
                },
                "number_suffix": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "number-suffix",
                    "help": "House number suffix.",
                    "category": "unitary",
                },
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "name",
                    "help": "Name (residence and office occupant).",
                    "category": "unitary",
                },
                "building": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "building",
                    "help": "Building (structure).",
                    "category": "unitary",
                },
                "room": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "room",
                    "help": "Room number.",
                    "category": "unitary",
                },
                "language": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "language",
                    "help": "Language.",
                    "category": "unitary",
                },
                "additional_code": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "additional-code",
                    "help": "Additional code.",
                    "category": "unitary",
                },
                "country": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "country",
                    "help": "The two-letter ISO 3166 country code in capital ASCII letters eg. US,CA,DK,DE.",
                    "category": "unitary",
                },
                "script": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "script",
                    "help": "Script used to present the address information.",
                    "category": "unitary",
                },
                "city_division": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "city-division",
                    "help": "City division,borough,city district,ward,or chou (JP).",
                    "category": "unitary",
                },
                "trailing_str_suffix": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "trailing-str-suffix",
                    "help": "Trailing street suffix.",
                    "category": "unitary",
                },
                "landmark": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "landmark",
                    "help": "Landmark or vanity address.",
                    "category": "unitary",
                },
                "block": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "block",
                    "help": "Neighborhood or block.",
                    "category": "unitary",
                },
                "postal_community": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "postal-community",
                    "help": "Postal community name.",
                    "category": "unitary",
                },
            },
            "name": "address-civic",
            "help": "Configure Location Civic Address.",
            "category": "complex",
        },
        "elin_number": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "elin_number": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "elin-number",
                    "help": "Configure Elin Callback Number,10 to 20 bytes numerial string.",
                    "category": "unitary",
                }
            },
            "name": "elin-number",
            "help": "Configure Location ELIN Number.",
            "category": "complex",
        },
        "name": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "name": "name",
            "help": "Unique Location Item Name.",
            "category": "unitary",
        },
        "coordinates": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "latitude": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "latitude",
                    "help": "Floating point start with ( +/- )  or end with ( N or S ) eg. +/-16.67 or 16.67N.",
                    "category": "unitary",
                },
                "datum": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "WGS84"},
                        {"value": "NAD83"},
                        {"value": "NAD83/MLLW"},
                    ],
                    "name": "datum",
                    "help": "WGS84,NAD83,NAD83/MLLW .",
                    "category": "unitary",
                },
                "altitude": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "altitude",
                    "help": "+/- Floating point no. eg. 117.47.",
                    "category": "unitary",
                },
                "altitude_unit": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "m"}, {"value": "f"}],
                    "name": "altitude-unit",
                    "help": "m ( meters),f ( floors).",
                    "category": "unitary",
                },
                "longitude": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "name": "longitude",
                    "help": "Floating point start with ( +/- )  or end with ( E or W ) eg. +/-26.789 or 26.789E.",
                    "category": "unitary",
                },
            },
            "name": "coordinates",
            "help": "Configure Location GPS Coordinates.",
            "category": "complex",
        },
    },
    "v_range": [["v7.0.0", ""]],
    "name": "location",
    "help": "Configure Location table.",
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
        "system_location": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_location"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_location"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_location"
        )
        is_error, has_changed, result, diff = fortiswitch_system(
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
