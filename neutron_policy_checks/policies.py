# SPDX-License-Identifier: Apache-2.0

"""Policy decisions behind the oslo.policy checks in ``checks.py``.

Each function takes a neutron context and the policy target, reads whatever it
needs from the database, and returns a :class:`Decision`.
"""

import collections

from neutron.db.models import allowed_address_pair as models
from neutron.objects import ports as port_obj
from neutron.objects import securitygroup as sg_obj
from neutron.objects.port.extensions import allowedaddresspairs as aap_obj
from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

Decision = collections.namedtuple("Decision", ["allowed", "message"])

ALLOW = Decision(True, "True")


def deny(message):
    return Decision(False, message)


def context_from_creds(creds):
    """Build the requester's context from oslo.policy credentials."""
    return context.Context(user_id=creds["user_id"], project_id=creds["project_id"])


def address_pair(ctx, target, strict=True):
    """Check if allowed address pair set to valid target IP address and MAC"""
    if "attributes_to_update" not in target:
        LOG.info("No attributes_to_update found, skip check.")
        return ALLOW
    elif "allowed_address_pairs" not in target["attributes_to_update"]:
        LOG.info(
            "No allowed_address_pairs in update targets "
            f"for port {target['id']}, skip check."
        )
        return ALLOW
    if target.get("allowed_address_pairs", []) == []:
        LOG.info("Empty address pair to check on, skip check.")
        return ALLOW

    # TODO(rlin): Ideally we should limit this policy check only if its a provider network

    ports = port_obj.Port.get_objects(ctx, id=[target["id"]])
    if len(ports) == 0:
        # Note(ricolin): This happens with ports that are not well defined
        # and missing context factors like project_id.
        # Which port usually created by services and design for internal
        # uses. We can skip this check and avoid blocking services.
        msg = f"Can't fetch port {target['id']} with current context, skip this check."
        LOG.info(msg)
        return deny(msg)

    verify_address_pairs = []
    target_port = ports[0]
    db_pairs = (
        target_port.allowed_address_pairs if target_port.allowed_address_pairs else []
    )
    target_pairs = target.get("allowed_address_pairs", [])
    db_pairs_dict = {str(p.ip_address): str(p.mac_address) for p in db_pairs}
    for pair in target_pairs:
        if pair.get("ip_address") not in db_pairs_dict:
            verify_address_pairs.append(pair)
        elif (
            strict
            and pair.get("mac_address")
            and db_pairs_dict[pair.get("ip_address")] != pair.get("mac_address")
        ):
            verify_address_pairs.append(pair)

    for allowed_address_pair in verify_address_pairs:
        if strict and "mac_address" in allowed_address_pair:
            with db_api.CONTEXT_READER.using(ctx):
                ports = port_obj.Port.get_objects(
                    ctx,
                    network_id=target["network_id"],
                    project_id=target["project_id"],
                    mac_address=allowed_address_pair["mac_address"],
                )
            if len(ports) != 1:
                msg = (
                    "Zero or Multiple match port found with "
                    f"MAC address {allowed_address_pair['mac_address']}."
                )
                LOG.info(f"{msg} Fail check.")
                return deny(msg)
        else:
            with db_api.CONTEXT_READER.using(ctx):
                ports = port_obj.Port.get_objects(
                    ctx,
                    network_id=target["network_id"],
                    project_id=target["project_id"],
                )
        if "ip_address" in allowed_address_pair:
            found_match = False
            for port in ports:
                fixed_ips = [str(fixed_ip["ip_address"]) for fixed_ip in port.fixed_ips]
                if allowed_address_pair["ip_address"] in fixed_ips:
                    found_match = True
                    break
            if found_match:
                LOG.debug("Valid address pair.")
                continue
            msg = (
                "IP address not exists in network from project "
                f"{target['project_id']}."
            )
            LOG.info(f"{msg} Fail check.")
            return deny(msg)
    LOG.info("Valid port for address pairs, passed check.")
    return ALLOW


def port_update(ctx, target, strict=True):
    """Check if IP or MAC has address pair dependency

    Make sure we allow update IP or MAC only if they don't
    have any allowed address pair dependency
    """
    if "attributes_to_update" not in target:
        LOG.info("No attributes_to_update found, skip check.")
        return ALLOW
    elif (not strict or ("mac_address" not in target["attributes_to_update"])) and (
        "fixed_ips" not in target["attributes_to_update"]
    ):
        LOG.info(
            f"No {'mac_address or fixed_ips' if strict else 'fixed_ips'} in "
            f"update targets for port {target['id']}, skip check."
        )
        return ALLOW

    with db_api.CONTEXT_READER.using(ctx):
        ports = port_obj.Port.get_objects(ctx, id=[target["id"]])
        if len(ports) == 0:
            # Note(ricolin): This happens with ports that are not well defined
            # and missing context factors like project_id.
            # Which port usually created by services and design for internal
            # uses. We can skip this check and avoid blocking services.
            LOG.info(
                f"Can't fetch port {target['id']} with current "
                "context, skip this check."
            )
            return ALLOW
    return _check_address_pair_match(
        ctx,
        target["id"],
        str(ports[0].network_id),
        ports[0].fixed_ips,
        mac_address=str(ports[0].mac_address) if strict else None,
        success_msg=f"Update check passed for port: {target['id']}",
    )


def port_delete(ctx, target, strict=True):
    return _check_address_pair_match(
        ctx,
        target["id"],
        str(target["network_id"]),
        target["fixed_ips"],
        mac_address=str(target["mac_address"]) if strict else None,
        success_msg=f"Delete check passed for port: {target['id']}",
    )


def _check_address_pair_match(
    ctx, port_id, network_id, fixed_ips, mac_address=None, success_msg=""
):
    fixed_ips = [str(fixed_ip["ip_address"]) for fixed_ip in fixed_ips]
    with db_api.CONTEXT_READER.using(ctx):
        query = ctx.session.query(models.AllowedAddressPair).filter(
            models.AllowedAddressPair.ip_address.in_(fixed_ips)
        )
        if mac_address:
            query = query.filter(
                models.AllowedAddressPair.mac_address.in_([mac_address])
            )

        pairs = [
            aap_obj.AllowedAddressPair._load_object(ctx, db_obj)
            for db_obj in query.all()
        ]
        if len(pairs) > 0:
            for pair in pairs:
                port = port_obj.Port.get_object(ctx, id=pair.port_id)
                if port and port.network_id == network_id:
                    msg = f"Address pairs dependency found for port: {port_id}"
                    LOG.info(msg)
                    return deny(msg)

    LOG.info(success_msg)
    return ALLOW


QUARANTINE_PROTECTED_ATTRIBUTES = frozenset(
    ("security_groups", "allowed_address_pairs", "port_security_enabled")
)


def quarantine(ctx, target, security_group="quarantine"):
    """Block network changes on a port that an admin has quarantined.

    A port is quarantined when it carries a security group with the given
    name that is owned by a project other than the port's. Tenants cannot
    attach another project's non-shared security group to their own port, so
    such a group can only have been put there by an admin.
    """
    attrs = set(target.get("attributes_to_update") or ())
    blocked = sorted(attrs & QUARANTINE_PROTECTED_ATTRIBUTES)
    if not blocked:
        return ALLOW

    # The quarantine group belongs to another project and is not shared, so it
    # is only visible with an admin context.
    admin_ctx = ctx.elevated()
    with db_api.CONTEXT_READER.using(admin_ctx):
        port = port_obj.Port.get_object(admin_ctx, id=target["id"])
        if port is None or not port.security_group_ids:
            return ALLOW
        groups = sg_obj.SecurityGroup.get_objects(
            admin_ctx, id=list(port.security_group_ids)
        )

    for group in groups:
        if group.name == security_group and group.project_id != port.project_id:
            msg = (
                f"Port {target['id']} is quarantined by security group "
                f"{group.id}; changes to {', '.join(blocked)} are blocked."
            )
            LOG.info(msg)
            return deny(msg)
    return ALLOW
