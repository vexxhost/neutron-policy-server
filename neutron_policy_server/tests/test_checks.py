# SPDX-License-Identifier: Apache-2.0

"""Exercise the in-process checks through the real neutron API stack.

Requests go through neutron's API pipeline and PolicyHook, with the ML2
plugin on a SQLite database, so each check is loaded by oslo.policy from the
entry point and reads what it needs from the database.
"""

from neutron import policy
from neutron.tests.unit.plugins.ml2 import test_security_group
from oslo_policy import _checks
from oslo_policy import policy as oslo_policy

from neutron_policy_server import checks

ADMIN_PROJECT = "admin-project"
MEMBER = "(role:member and project_id:%(project_id)s and {check})"
RULES = {
    "update_port": "rule:admin_only or rule:service_api or "
    + MEMBER.format(check="quarantine:security_group=quarantine"),
    "delete_port": "rule:admin_only or rule:service_api or "
    + MEMBER.format(check="port_delete:strict=0"),
}


class TestInProcessChecks(test_security_group.Ml2SecurityGroupsTestCase):
    def setUp(self):
        super().setUp()
        policy.init()
        policy._ENFORCER.load_rules()
        policy._ENFORCER.set_rules(oslo_policy.Rules.from_dict(RULES), overwrite=False)

        self.net = self._make_network(self.fmt, "net", True)
        self.subnet = self._make_subnet(self.fmt, self.net, "10.0.0.1", "10.0.0.0/24")[
            "subnet"
        ]
        self.port = self._make_port(self.fmt, self.net["network"]["id"])["port"]
        self.tenant_sg = self._make_security_group(self.fmt, "web", "tenant sg")[
            "security_group"
        ]
        self.quarantine_sg = self._make_security_group(
            self.fmt,
            "quarantine",
            "admin quarantine",
            project_id=ADMIN_PROJECT,
            as_admin=True,
        )["security_group"]

    def _set_sgs(self, sg_ids, expected_code=200, as_admin=False):
        return self._update(
            "ports",
            self.port["id"],
            {"port": {"security_groups": sg_ids}},
            expected_code=expected_code,
            as_admin=as_admin,
        )

    def _quarantine(self):
        self._set_sgs([self.quarantine_sg["id"]], as_admin=True)

    def test_loaded_from_entry_point(self):
        extensions = _checks.get_extensions()
        self.assertIs(checks.AddressPairCheck, extensions["address_pair"])
        self.assertIs(checks.PortUpdateCheck, extensions["port_update"])
        self.assertIs(checks.PortDeleteCheck, extensions["port_delete"])
        self.assertIs(checks.QuarantineCheck, extensions["quarantine"])

    def test_port_delete_blocked_by_address_pair_dependency(self):
        ip = self.port["fixed_ips"][0]["ip_address"]
        self._make_port(
            self.fmt,
            self.net["network"]["id"],
            arg_list=("allowed_address_pairs",),
            allowed_address_pairs=[{"ip_address": ip}],
        )
        self._delete("ports", self.port["id"], expected_code=403)

    def test_port_delete_allowed_without_dependency(self):
        self._delete("ports", self.port["id"])

    def test_tenant_can_change_sgs_on_normal_port(self):
        self._set_sgs([self.tenant_sg["id"]])

    def test_tenant_cannot_change_sgs_on_quarantined_port(self):
        self._quarantine()
        self._set_sgs([self.tenant_sg["id"]], expected_code=403)
        self._set_sgs([], expected_code=403)

    def test_tenant_cannot_add_address_pairs_on_quarantined_port(self):
        self._quarantine()
        self._update(
            "ports",
            self.port["id"],
            {"port": {"allowed_address_pairs": [{"ip_address": "0.0.0.0/0"}]}},
            expected_code=403,
        )

    def test_tenant_can_rename_quarantined_port(self):
        self._quarantine()
        self._update("ports", self.port["id"], {"port": {"name": "renamed"}})

    def test_admin_can_release_quarantine(self):
        self._quarantine()
        self._set_sgs([self.tenant_sg["id"]], as_admin=True)
        self._set_sgs([self.tenant_sg["id"]])

    def test_tenant_cannot_attach_foreign_quarantine_sg(self):
        # Basis of the check: only an admin can put another project's
        # non-shared security group on a tenant's port.
        res = self._set_sgs([self.quarantine_sg["id"]], expected_code=404)
        self.assertIn("SecurityGroupNotFound", res["NeutronError"]["type"])

    def test_tenant_owned_quarantine_sg_does_not_lock(self):
        own = self._make_security_group(self.fmt, "quarantine", "tenant made")[
            "security_group"
        ]
        self._set_sgs([own["id"]])
        self._set_sgs([self.tenant_sg["id"]])
