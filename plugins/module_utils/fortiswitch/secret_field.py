from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


secret_fields = [
    "password", "passwd", "auth", "key", "secret", "router_key_chain", "auth_keychain", "system_password_policy",
    "uploadpass", "auth_keychain_hello", "auth_password_hello", "key_string", "authentication_key", "md5_keys"
]


def is_secret_field(key_name):
    if key_name in secret_fields:
        return True
    return False
