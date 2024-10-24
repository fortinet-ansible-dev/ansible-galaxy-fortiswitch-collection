==================================
Fortinet.Fortiswitch Release Notes
==================================

.. contents:: Topics


v1.2.5
======

Release Summary
---------------

patch release of 1.2.5

Major Changes
-------------

- Support new version 7.6.0
- Update README.md to satisfy the latest Ansible collection requirements.

Bugfixes
--------

- Fix the issue while unsetting allowaccess in `fortiswitch_system_interface`

v1.2.4
======

Release Summary
---------------

patch release of 1.2.4

Major Changes
-------------

- Add warning on the document for the module `fortiswitch_system_proxy_arp` to indicate that the module is not used for production purpose.
- Improve the no_log logic to expose all the non-sensitive data to users.
- Support Ansible 2.17.
- Support multiple valus for the parameter of `ip6_allowaccess` in the module of `fortiswitch_system_interface`.
- Support new FortiSwitch versions 7.4.3.
- Update the required Ansible version to 2.15.
- Update the supported version for the module with version number instead of latest.

v1.2.3
======

Release Summary
---------------

patch release of 1.2.3

Major Changes
-------------

- Support new FortiSwitch versions 7.4.2
- Update supported fortiswitch versions and parameters with version ranges instead of fixed versions

Bugfixes
--------

- Fix Github issues
- Fix errors in sanity-test and ansible-lint

v1.2.2
======

Release Summary
---------------

patch release of 1.2.2

Major Changes
-------------

- Format the contents in the changelog.yaml.
- Support new FortiSwitch version 7.4.1.
- Update Ansible version from 2.9 to 2.14.
- Update the requirement.txt file to specify the sphinx_rtd_theme==1.3.0.

v1.2.1
======

Release Summary
---------------

patch release of 1.2.1

Major Changes
-------------

- Add a readthedocs configuration file
- Support new FortiSwitch versions 7.2.4, 7.2.5 and 7.4.0.

v1.2.0
======

Release Summary
---------------

patch release of 1.2.0

Major Changes
-------------

- Support new FortiSwitch versions 7.2.1, 7.2.2 and 7.2.3.

v1.1.3
======

Release Summary
---------------

patch release of 1.1.3

Major Changes
-------------

- Support new FortiSwitch versions 7.0.4, 7.0.5 and 7.0.6.

Bugfixes
--------

- Fix Github issue
- Fix errors when deleting an object.
- Fix multiple values issue in the module ``fortiswitch_system_interface``.
- Fix sanity-test errors.

v1.1.2
======

Release Summary
---------------

patch release of 1.1.2

Major Changes
-------------

- Support Diff feature in check_mode.
- Support check_mode for configuration modules.

Bugfixes
--------

- Disable log information for some sensitive parameters.
- Fix bugs in the comparison function.
- Fix member_operation issue.
- Fix str_obj_has_no_attribute_items issue.
- Remove invalid value in a list or dict.

v1.1.1
======

Release Summary
---------------

patch release of 1.1.1

Bugfixes
--------

- Add GPLv3 License.
- Add default value for enable_log param and unify the type in both doc and spec.
- Fix import errors in sanity-test.
- Fix no-log-needed errors in sanity-test.
- Fix paramter-list-no-elements errors in sanity-test.
- Fix redundant state param in the some of the Examples.
- Fix the issue of empty children in execute schema.
- Fix unnecessary comprehension for FACT_DETAIL_SUBSETS.
- Support multiple values for allowaccess in the module ``fortiswitch_system_interface``.
- Support syntax for Python 2.7.
- Use collection version in the doc section.

v1.1.0
======

Release Summary
---------------

minor release of 1.1.0

Major Changes
-------------

- Support ``execute`` schema including backup, restore and other features.

v1.0.1
======

Release Summary
---------------

patch release of 1.0.1

Major Changes
-------------

- Supports FSW versions 7.0.1, 7.0.2 and 7.0.3

v1.0.0
======

Release Summary
---------------

major release of 1.0.0

Major Changes
-------------

- Support Exporting playbook for configuration modules.
- Support FortiSwitch 7.0.0.
- Support all the Configuration Modules and Monitor Modules.
- Support fact retrieval feature, ``fortios_monitor_fact`` and ``fortios_log_fact``.
