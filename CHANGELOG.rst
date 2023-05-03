==================================
Fortinet.Fortiswitch Release Notes
==================================

.. contents:: Topics


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
