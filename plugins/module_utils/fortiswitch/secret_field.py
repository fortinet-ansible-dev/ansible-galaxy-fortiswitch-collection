from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


secret_fields = [
    "password", "passwd", "auth", "key", "secret", "router_key_chain",
    "auth_keychain", "system_password_policy", "uploadpass", "auth_keychain_hello",
    "auth_password_hello", "key_string", "authentication_key", "md5_keys",
    "psksecret", "auth_keychain_area", "auth_keychain_domain", "auth_password_area",
    "auth_password_domain", "password_expire", "alicloud_access_key_secret",
    "aws_api_key", "azure_api_key", "ldap_password", "private_key", "scep_password",
    "radius_coa_secret", "secondary_secret"
]


def is_secret_field(key_name):
    if key_name in secret_fields:
        return True
    return False
