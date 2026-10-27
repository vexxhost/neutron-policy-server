=====================
Neutron Policy Checks
=====================

``oslo.policy`` checks for Neutron policies that the default policy language
can't express, because they need to look at other ports or security groups in
the database.

The checks are registered on the ``oslo.policy.rule_checks`` entry point, so
installing this package next to Neutron is enough: they run inside
``neutron-server`` as part of normal policy enforcement and are referenced
from ``policy.yaml`` by name.

This project was previously ``neutron-policy-server``, which ran the same
checks as a separate HTTP service called through ``http://`` policy rules.
Replace those rules with the checks below:

.. list-table::
   :header-rows: 1

   * - ``neutron-policy-server`` rule
     - ``neutron-policy-checks`` rule
   * - ``http://neutron-server:9697/address-pair``
     - ``address_pair:strict=1``
   * - ``http://neutron-server:9697/port-update``
     - ``port_update:strict=1``
   * - ``http://neutron-server:9697/port-delete``
     - ``port_delete:strict=1``

You can reference a policy example in
https://github.com/vexxhost/atmosphere/blob/main/roles/neutron/vars/main.yml

-------------------------------------------
Allowed Address Pairs for Provider Networks
-------------------------------------------

The default Neutron policy does not allow the use of allowed address pairs for
provider networks.  However, in a use case where you need to run a highly
available service on a provider network, you may need to use allowed address
pairs to allow multiple instances to share the same IP address.

The ``address_pair``, ``port_update`` and ``port_delete`` checks allow the use
of allowed address pairs for provider networks under these circumstances:

- Users can modify an ``allowed_address_pairs`` attribute to their port if they
  own another port on the same network with the same MAC & IP address.
- Users cannot delete a port if another port on the same network has an
  ``allowed_address_pairs`` attribute with the same MAC & IP address.
- Users cannot modify the ``fixed_ips`` attribute of a port if another port on
  the same network has an ``allowed_address_pairs`` attribute with the IP.

Here is an example ``policy.yaml`` file for Neutron:

.. code-block:: yaml

  delete_port: ((rule:admin_only) or (rule:service_api) or role:member and rule:network_owner
    or role:member and project_id:%(project_id)s) and port_delete:strict=1
  update_port:allowed_address_pairs: ((rule:admin_only) or (role:member and rule:network_owner)
    or role:manager and project_id:%(project_id)s) or (role:member and project_id:%(project_id)s
    and address_pair:strict=1)
  update_port:allowed_address_pairs:ip_address: ((rule:admin_only) or (role:member and
    rule:network_owner) or role:manager and project_id:%(project_id)s) or (role:member
    and project_id:%(project_id)s)
  update_port:allowed_address_pairs:mac_address: ((rule:admin_only) or (role:member
    and rule:network_owner) or role:manager and project_id:%(project_id)s) or (role:member
    and project_id:%(project_id)s)
  update_port:fixed_ips: ((rule:admin_only) or (rule:service_api) or role:manager and
    project_id:%(project_id)s or role:member and rule:network_owner) and port_update:strict=1
  update_port:mac_address: ((rule:admin_only) or (rule:service_api) or role:manager
    and project_id:%(project_id)s) and port_update:strict=1

All rules above contain the original rules with a check added. You can make the
check a hard condition like above if you want the protection for allowed address
pairs to apply across network ownership when updating or deleting ports.

-----------
Strict Mode
-----------

By default the MAC address also needs to match when adding allowed address
pairs, updating ports and deleting ports. Set ``strict=0`` to disable this, for
example ``port_delete:strict=0``. With strict mode disabled, a policy passes
with only an IP address match. This is useful for HA setups where one IP
address moves between two instances.

----------
Quarantine
----------

The ``quarantine`` check blocks changes to ``security_groups``,
``allowed_address_pairs`` and ``port_security_enabled`` on a quarantined port.
A port is quarantined when it carries a security group with the configured
name (``quarantine`` by default) that belongs to a different project than the
port. Users cannot attach another project's non-shared security group to their
own port, so only an administrator can quarantine a port.

.. code-block:: yaml

  update_port: (rule:admin_only) or (rule:service_api) or (role:member and
    project_id:%(project_id)s and quarantine:security_group=quarantine)

-----------------
Known Limitations
-----------------

Current limitation for cross-ownership network port address pair binding only
allows fixed IP address format x.x.x.x without CIDR format like
`/32` or `/24`. And the reason for that limitation is, when using CIDR like
`10.10.10.0/24`, it will lock all ports with IPs under 10.10.10.0/24 to prevent
delete actions. But that’s pretty damage to security consider user doesn’t get
the ownership to the entire network. Currently it can directly put in fixed IP
address like 10.10.10.4.
Also worth to mentioned that, CIDR format limitation are not affected on any
existing use cases (which user actually owned the network).
So network owner can add allowed address pair with CIDRs like 10.10.10.0/24.
