# SPDX-License-Identifier: Apache-2.0

"""oslo.policy checks for neutron-server.

oslo.policy loads these through the ``oslo.policy.rule_checks`` entry point,
so they run inside the neutron-server API worker during normal policy
enforcement. Each replaces an ``http:`` rule of the former neutron-policy-server
sidecar, or adds a new policy::

    http://neutron-server:9697/address-pair?strict=0  ->  address_pair:strict=0
    http://neutron-server:9697/port-update            ->  port_update:strict=1
    http://neutron-server:9697/port-delete?strict=0   ->  port_delete:strict=0
                                                          quarantine:security_group=quarantine
"""

import copy

from oslo_log import log as logging
from oslo_policy import policy
from oslo_serialization import jsonutils

LOG = logging.getLogger(__name__)


def _normalize(target):
    """Give the decision the same target an ``http:`` rule would send.

    Mirrors oslo.policy's HttpCheck payload, which the decisions were written
    against: ``object()`` sentinels such as
    ATTR_NOT_SPECIFIED become ``{}`` and the result goes through a JSON round
    trip, which turns non-JSON values (UUIDs, netaddr objects) into strings.
    """
    temp = copy.deepcopy(target)
    for key, value in target.items():
        if type(value) is object:
            temp[key] = {}
    return jsonutils.loads(jsonutils.dumps(temp))


class _PolicyCheck(policy.Check):
    """Base for checks written as ``<kind>:<key>=<value>[,<key>=<value>]``."""

    options = {}

    def __init__(self, kind, match):
        super().__init__(kind, match)
        self.values = dict(self.options)
        for item in filter(None, match.split(",")):
            key, sep, value = item.partition("=")
            if not sep or key not in self.options:
                LOG.warning("Ignoring unknown option %r in %s:%s", item, kind, match)
                continue
            self.values[key] = value

    def decide(self, policies, ctx, target):
        raise NotImplementedError

    def evaluate(self, target, creds):
        # Imported lazily: oslo.policy loads every installed rule_checks
        # extension when it parses rules, including in processes that never
        # set up neutron's database.
        from neutron_policy_checks import policies

        return self.decide(policies, policies.context_from_creds(creds), target)

    def __call__(self, target, creds, enforcer, current_rule=None):
        try:
            return self.evaluate(_normalize(target), creds).allowed
        except Exception:
            # Fail closed: an error must not grant access.
            LOG.exception("Policy check %s:%s failed, denying", self.kind, self.match)
            return False


class _StrictCheck(_PolicyCheck):
    options = {"strict": "1"}

    @property
    def strict(self):
        # Anything that isn't an integer means strict, as it always has.
        try:
            return bool(int(self.values["strict"]))
        except ValueError:
            return True


class AddressPairCheck(_StrictCheck):
    def decide(self, policies, ctx, target):
        return policies.address_pair(ctx, target, strict=self.strict)


class PortUpdateCheck(_StrictCheck):
    def decide(self, policies, ctx, target):
        return policies.port_update(ctx, target, strict=self.strict)


class PortDeleteCheck(_StrictCheck):
    def decide(self, policies, ctx, target):
        return policies.port_delete(ctx, target, strict=self.strict)


class QuarantineCheck(_PolicyCheck):
    options = {"security_group": "quarantine"}

    def decide(self, policies, ctx, target):
        return policies.quarantine(
            ctx, target, security_group=self.values["security_group"]
        )
