# SPDX-License-Identifier: Apache-2.0

import json
import sys

from flask import Flask, Response, g, request
from keystoneauth1 import loading as ks_loading
from neutron.common import config
from neutron.conf import common as neutron_common_conf
from neutron.db.models import allowed_address_pair as models
from neutron.objects import ports as port_obj
from neutron.objects.port.extensions import allowedaddresspairs as aap_obj
from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_config import cfg
from oslo_log import log as logging

# Nova client for checking instance lock state
try:
    from novaclient import api_versions
    from novaclient import client as nova_client
    from novaclient.exceptions import NotFound

    HAS_NOVA_CLIENT = True
except ImportError:
    HAS_NOVA_CLIENT = False

# Security group handling. NOTE: the module is ``securitygroup`` (singular);
# ``securitygroups`` does not exist and made this import fail silently, leaving
# sg_obj undefined so the quarantine SG name match raised NameError and the
# check fell through to "allow".
try:
    from neutron.objects import securitygroup as sg_obj

    HAS_NEUTRON_SG = True
except ImportError:
    HAS_NEUTRON_SG = False

config.register_common_config_options()
config.init(sys.argv[1:])
config.setup_logging()

# Register the [nova] auth/session options so the policy server can build an
# authenticated Nova client the same way neutron's own nova notifier does. Used
# to read the VM lock state for quarantine enforcement. neutron.conf (with its
# [nova] section) is mounted into the sidecar.
if HAS_NOVA_CLIENT:
    neutron_common_conf.register_nova_opts(cfg.CONF)
    ks_loading.register_auth_conf_options(cfg.CONF, "nova")
    ks_loading.register_session_conf_options(cfg.CONF, "nova")

LOG = logging.getLogger(__name__)

app = Flask(__name__)


@app.before_request
def fetch_context():
    # Skip detail data fetch if we're running health check
    if request.path == "/health":
        g.ctx = context.Context()
        return
    content_type = request.headers.get(
        "Content-Type", "application/x-www-form-urlencoded"
    )
    if content_type == "application/x-www-form-urlencoded":
        data = request.form.to_dict()
        g.target = json.loads(data.get("target"))
        g.creds = json.loads(data.get("credentials"))
        g.rule = json.loads(data.get("rule"))
    elif content_type == "application/json":
        data = request.json
        g.target = data.get("target")
        g.creds = data.get("credentials")
        g.rule = data.get("rule")
    g.ctx = context.Context(
        user_id=g.creds["user_id"], project_id=g.creds["project_id"]
    )


@app.route("/address-pair", methods=["POST"])
def enforce_address_pair():
    """Check if allowed address pair set to valid target IP address and MAC"""
    # Check only IP address if strict is 0
    strict = bool(request.args.get("strict", default=1, type=int))
    if "attributes_to_update" not in g.target:
        LOG.info("No attributes_to_update found, skip check.")
        return Response("True", status=200, mimetype="text/plain")
    elif "allowed_address_pairs" not in g.target["attributes_to_update"]:
        LOG.info(
            "No allowed_address_pairs in update targets "
            f"for port {g.target['id']}, skip check."
        )
        return Response("True", status=200, mimetype="text/plain")
    if g.target.get("allowed_address_pairs", []) == []:
        LOG.info("Empty address pair to check on, skip check.")
        return Response("True", status=200, mimetype="text/plain")

    # TODO(rlin): Ideally we should limit this policy check only if its a provider network

    ports = port_obj.Port.get_objects(g.ctx, id=[g.target["id"]])
    if len(ports) == 0:
        # Note(ricolin): This happens with ports that are not well defined
        # and missing context factors like project_id.
        # Which port usually created by services and design for internal
        # uses. We can skip this check and avoid blocking services.
        msg = (
            f"Can't fetch port {g.target['id']} with current "
            "context, skip this check."
        )
        LOG.info(msg)
        return Response(msg, status=403, mimetype="text/plain")

    verify_address_pairs = []
    target_port = ports[0]
    db_pairs = (
        target_port.allowed_address_pairs if target_port.allowed_address_pairs else []
    )
    target_pairs = g.target.get("allowed_address_pairs", [])
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
            with db_api.CONTEXT_READER.using(g.ctx):
                ports = port_obj.Port.get_objects(
                    g.ctx,
                    network_id=g.target["network_id"],
                    project_id=g.target["project_id"],
                    mac_address=allowed_address_pair["mac_address"],
                )
            if len(ports) != 1:
                msg = (
                    "Zero or Multiple match port found with "
                    f"MAC address {allowed_address_pair['mac_address']}."
                )
                LOG.info(f"{msg} Fail check.")
                return Response(msg, status=403, mimetype="text/plain")
        else:
            with db_api.CONTEXT_READER.using(g.ctx):
                ports = port_obj.Port.get_objects(
                    g.ctx,
                    network_id=g.target["network_id"],
                    project_id=g.target["project_id"],
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
            msg = f"IP address not exists in network from project {g.target['project_id']}."
            LOG.info(f"{msg} Fail check.")
            return Response(
                msg,
                status=403,
                mimetype="text/plain",
            )
    LOG.info("Valid port for address pairs, passed check.")
    return Response("True", status=200, mimetype="text/plain")


@app.route("/port-update", methods=["POST"])
def enforce_port_update():
    """Check if IP or MAC has address pair dependency

    Make sure we allow update IP or MAC only if they don't
    have any allowed address pair dependency
    """
    # Check only IP address if strict is 0
    strict = bool(request.args.get("strict", default=1, type=int))

    if "attributes_to_update" not in g.target:
        LOG.info("No attributes_to_update found, skip check.")
        return Response("True", status=200, mimetype="text/plain")
    elif (not strict or ("mac_address" not in g.target["attributes_to_update"])) and (
        "fixed_ips" not in g.target["attributes_to_update"]
    ):
        LOG.info(
            f"No {'mac_address or fixed_ips' if strict else 'fixed_ips'} in "
            f"update targets for port {g.target['id']}, skip check."
        )
        return Response("True", status=200, mimetype="text/plain")

    with db_api.CONTEXT_READER.using(g.ctx):
        ports = port_obj.Port.get_objects(g.ctx, id=[g.target["id"]])
        if len(ports) == 0:
            # Note(ricolin): This happens with ports that are not well defined
            # and missing context factors like project_id.
            # Which port usually created by services and design for internal
            # uses. We can skip this check and avoid blocking services.
            LOG.info(
                f"Can't fetch port {g.target['id']} with current "
                "context, skip this check."
            )
            return Response("True", status=200, mimetype="text/plain")
    return _check_address_pair_match(
        g.ctx,
        str(ports[0].network_id),
        ports[0].fixed_ips,
        mac_address=str(ports[0].mac_address) if strict else None,
        success_msg=f"Update check passed for port: {g.target['id']}",
    )


@app.route("/port-delete", methods=["POST"])
def enforce_port_delete():
    # Check only IP address if strict is 0
    strict = bool(request.args.get("strict", default=1, type=int))
    return _check_address_pair_match(
        g.ctx,
        str(g.target["network_id"]),
        g.target["fixed_ips"],
        mac_address=str(g.target["mac_address"]) if strict else None,
        success_msg=f"Delete check passed for port: {g.target['id']}",
    )


def _check_address_pair_match(
    ctx, network_id, fixed_ips, mac_address=None, success_msg=""
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
                    msg = (
                        "Address pairs dependency found for port: " f"{g.target['id']}"
                    )
                    LOG.info(msg)
                    return Response(msg, status=403, mimetype="text/plain")

    LOG.info(success_msg)
    return Response("True", status=200, mimetype="text/plain")


# Microversion 2.9 is the first that includes the ``locked`` attribute in the
# server representation; with anything lower ``server.locked`` is absent and the
# quarantine check would always read False.
NOVA_API_VERSION = "2.9"
_NOVA_SESSION = None


def _get_nova_client():
    """Build an authenticated Nova client from the [nova] section of
    neutron.conf, the same way neutron's own nova notifier does. The keystone
    session is cached across requests."""
    global _NOVA_SESSION
    if not HAS_NOVA_CLIENT:
        return None
    try:
        if _NOVA_SESSION is None:
            auth = ks_loading.load_auth_from_conf_options(cfg.CONF, "nova")
            _NOVA_SESSION = ks_loading.load_session_from_conf_options(
                cfg.CONF, "nova", auth=auth
            )
        return nova_client.Client(
            api_versions.APIVersion(NOVA_API_VERSION),
            session=_NOVA_SESSION,
            region_name=cfg.CONF.nova.region_name,
            endpoint_type=cfg.CONF.nova.endpoint_type,
        )
    except Exception as e:
        LOG.error(f"Failed to create Nova client: {e}")
        return None


def _is_vm_quarantined(instance_id, ctx):
    """Check if a VM is quarantined (locked with quarantine security group)."""
    if not HAS_NOVA_CLIENT:
        LOG.warning("Nova client not available, skipping quarantine check")
        return False

    try:
        nova = _get_nova_client()
        LOG.debug("[quarantine-dbg] nova_client_available=%s", bool(nova))
        if not nova:
            return False

        # Check if VM is locked (primary indicator of quarantine)
        server = nova.servers.get(instance_id)
        locked = getattr(server, "locked", None)
        LOG.debug("[quarantine-dbg] instance=%s locked=%r", instance_id, locked)
        if not locked:
            return False

        # Look up the ports and their security groups with an ELEVATED (admin)
        # context. The quarantine SG is typically owned by the admin project and
        # NOT shared, so the requesting member's context cannot read it and
        # SecurityGroup.get_object() would return None, making the name match
        # silently fail.
        admin_ctx = ctx.elevated()

        with db_api.CONTEXT_READER.using(admin_ctx):
            ports = port_obj.Port.get_objects(admin_ctx, device_id=[instance_id])
            LOG.debug(
                "[quarantine-dbg] instance=%s ports=%s",
                instance_id,
                [str(p.id) for p in ports],
            )

            if not ports:
                return False

            quarantine_sg_name = "quarantine"  # Default quarantine SG name
            for port in ports:
                sg_ids = list(port.security_group_ids or [])
                LOG.debug("[quarantine-dbg] port=%s sg_ids=%s", port.id, sg_ids)
                for sg_id in sg_ids:
                    try:
                        sg = sg_obj.SecurityGroup.get_object(admin_ctx, id=sg_id)
                    except Exception:
                        LOG.exception(
                            "[quarantine-dbg] sg lookup failed for %s", sg_id
                        )
                        continue
                    LOG.debug(
                        "[quarantine-dbg] sg=%s name=%r",
                        sg_id,
                        getattr(sg, "name", None),
                    )
                    if sg and sg.name == quarantine_sg_name:
                        LOG.debug("[quarantine-dbg] MATCH quarantine sg on port %s", port.id)
                        return True

        return False

    except NotFound:
        LOG.debug("[quarantine-dbg] instance %s not found in Nova", instance_id)
        return False
    except Exception:
        LOG.exception(
            "[quarantine-dbg] error checking quarantine status for %s", instance_id
        )
        # If we can't determine quarantine status, be conservative
        return False


@app.route("/port-update-quarantine", methods=["POST"])
def enforce_port_update_quarantine():
    """Block security-group / allowed-address-pair changes on a quarantined VM.

    A VM is quarantined when it is Nova-locked AND one of its ports carries a
    security group named "quarantine". Only project members reach this rule
    (admins/service bypass it in policy.yaml), so denying here stops a tenant
    from lifting their own network isolation. Any other update returns "True".
    """
    # Only security-group / address-pair changes are relevant.
    attrs = g.target.get("attributes_to_update") or []
    LOG.debug(
        "[quarantine-dbg] ENTER port=%s attrs=%s new_security_groups=%s",
        g.target.get("id"),
        attrs,
        g.target.get("security_groups"),
    )
    if not any(a in attrs for a in ("security_groups", "allowed_address_pairs")):
        LOG.debug("[quarantine-dbg] no security_groups/allowed_address_pairs change -> allow")
        return Response("True", status=200, mimetype="text/plain")

    # device_owner/device_id are NOT carried in the policy target for a
    # security-groups-only update (they have defaults and are not
    # required_by_policy), so resolve them from the port in the DB.
    with db_api.CONTEXT_READER.using(g.ctx):
        ports = port_obj.Port.get_objects(g.ctx, id=[g.target["id"]])
    if not ports:
        LOG.debug(
            "[quarantine-dbg] port %s not visible to requester context -> allow",
            g.target.get("id"),
        )
        return Response("True", status=200, mimetype="text/plain")

    device_owner = ports[0].device_owner or ""
    device_id = ports[0].device_id or ""
    LOG.debug(
        "[quarantine-dbg] port=%s device_owner=%r device_id=%r",
        g.target.get("id"),
        device_owner,
        device_id,
    )
    if not device_owner.startswith("compute:") or not device_id:
        LOG.debug("[quarantine-dbg] port not attached to a compute instance -> allow")
        return Response("True", status=200, mimetype="text/plain")

    quarantined = _is_vm_quarantined(device_id, g.ctx)
    LOG.debug("[quarantine-dbg] _is_vm_quarantined(%s)=%s", device_id, quarantined)
    if quarantined:
        msg = (
            f"VM {device_id} is quarantined; security group / allowed address "
            "pair changes are blocked."
        )
        LOG.info(msg)
        return Response(msg, status=403, mimetype="text/plain")

    return Response("True", status=200, mimetype="text/plain")


@app.route("/health", methods=["GET"])
def health_check():
    with db_api.CONTEXT_READER.using(g.ctx):
        port_obj.Port.get_objects(g.ctx, id=["neutron_policy_server_health_check"])
        return Response(status=200)


def create_app():
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=9697)
