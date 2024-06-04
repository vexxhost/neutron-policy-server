=====================
Neutron Policy Server
=====================

This is a simple server which can be used to manage complex Neutron policies
which are not possible to be managed using the default Neutron ``policy.json``
file due to the lack of programmatic control.  It covers the following use
cases:

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
