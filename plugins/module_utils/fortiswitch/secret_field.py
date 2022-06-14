from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


def is_secret_field(key_name):
    for patch in ["password", "passwd", "auth", "key", "secret", "router_key_chain", "auth_keychain", "system_password_policy"]:
        if patch in key_name:
            return True
    return False
