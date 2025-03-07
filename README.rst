=====================
Neutron Policy Server
=====================

This is a simple server which can be used to manage complex Neutron policies
which are not possible to be managed using the default Neutron ``policy.json``
file due to the lack of programmatic control.

You can reference policy example in
https://github.com/vexxhost/atmosphere/blob/main/roles/neutron/vars/main.yml#L125-L130

It covers the following use cases:

-------------------------------------------
Allowed Address Pairs for Provider Networks
-------------------------------------------

The default Neutron policy does not allow the use of allowed address pairs for
provider networks.  However, in a use case where you need to run a highly
available service on a provider network, you may need to use allowed address
pairs to allow multiple instances to share the same IP address.

This service intercepts the existing Neutron policy and allows the use of
allowed address pairs for provider networks under these circumstances:

- Users can modify an ``allowed_address_pairs`` attribute to their port if they
  own another port on the same network with the same MAC & IP address.
- Users cannot delete a port if another port on the same network has an
  ``allowed_address_pairs`` attribute with the same MAC & IP address.
- Users cannot modify the ``fixed_ips`` attribute of a port if another port on
  the same network has an ``allowed_address_pairs`` attribute with the IP.

---------
Use cases
---------

Here is a example policy.yaml file for Neutron to use Neutron policy server:

.. code-block:: yaml

  delete_port: ((rule:admin_only) or (rule:service_api) or role:member and rule:network_owner
    or role:member and project_id:%(project_id)s) and http://neutron-server:9697/port-delete
  update_port:allowed_address_pairs: ((rule:admin_only) or (role:member and rule:network_owner)
    or role:manager and project_id:%(project_id)s) or (role:member and project_id:%(project_id)s
    and http://neutron-server:9697/address-pair )
  update_port:allowed_address_pairs:ip_address: ((rule:admin_only) or (role:member and
    rule:network_owner) or role:manager and project_id:%(project_id)s) or (role:member
    and project_id:%(project_id)s)
  update_port:allowed_address_pairs:mac_address: ((rule:admin_only) or (role:member
    and rule:network_owner) or role:manager and project_id:%(project_id)s) or (role:member
    and project_id:%(project_id)s)
  update_port:fixed_ips: ((rule:admin_only) or (rule:service_api) or role:manager and
    project_id:%(project_id)s or role:member and rule:network_owner) and http://neutron-server:9697/port-update
  update_port:mac_address: ((rule:admin_only) or (rule:service_api) or role:manager
    and project_id:%(project_id)s) and http://neutron-server:9697/port-update

All rules above contains original rules with Neutron policy server URL integrated.
Environment can consider make Neutron policy server URL a hard condition like above if
wish the protection for allowed address pair exists across network ownership when
update or delete ports.

-----------
Strict Mode
-----------

By default MAC address need to also match for add allowed address pairs,
update port and delete port cases, but it can be disabled by provide query parameter
`strict=0`. Like `http://neutron-server:9697/port-delete?strict=0`.
With strict disabled, Mac address will not required to match.
Policy can pass with only IP address match. This is useful with some HA structure
which one IP might needs to switch cross two instances.

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
