from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


def remove_invalid_fields(input_data):
    if not isinstance(input_data, dict) and not isinstance(input_data, list):
        return input_data
    if isinstance(input_data, dict):
        result = {}
        for key, value in input_data.items():
            if value is None:
                continue
            result[key] = remove_invalid_fields(value)
        return result
    if isinstance(input_data, list):
        result = []
        for item in input_data:
            result.append(remove_invalid_fields(item))
        return result
