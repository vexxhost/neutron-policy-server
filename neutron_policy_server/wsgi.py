# SPDX-License-Identifier: Apache-2.0

import json
import sys

from flask import Flask, Response, g, request
from neutron.common import config
from neutron.db.models import allowed_address_pair as models
from neutron.objects import ports as port_obj
from neutron.objects.port.extensions import allowedaddresspairs as aap_obj
from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_log import log as logging

config.register_common_config_options()
config.init(sys.argv[1:])
config.setup_logging()

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
        msg = ""
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

        fixed_ips = [str(fixed_ip["ip_address"]) for fixed_ip in ports[0].fixed_ips]

        query = g.ctx.session.query(models.AllowedAddressPair).filter(
            models.AllowedAddressPair.ip_address.in_(fixed_ips)
        )
        if strict:
            query = query.filter(
                models.AllowedAddressPair.mac_address.in_([str(ports[0].mac_address)])
            )
        pairs = [
            aap_obj.AllowedAddressPair._load_object(context, db_obj)
            for db_obj in query.all()
        ]
    if len(pairs) > 0:
        msg = f"Address pairs dependency found for port: {g.target['id']}"
        LOG.info(msg)
        return Response(msg, status=403, mimetype="text/plain")
    LOG.info(f"Update check passed for port: {g.target['id']}")
    return Response("True", status=200, mimetype="text/plain")


@app.route("/port-delete", methods=["POST"])
def enforce_port_delete():
    # Check only IP address if strict is 0
    strict = bool(request.args.get("strict", default=1, type=int))
    fixed_ips = [str(fixed_ip["ip_address"]) for fixed_ip in g.target["fixed_ips"]]
    with db_api.CONTEXT_READER.using(g.ctx):
        query = g.ctx.session.query(models.AllowedAddressPair).filter(
            models.AllowedAddressPair.ip_address.in_(fixed_ips)
        )
        if strict:
            query = query.filter(
                models.AllowedAddressPair.mac_address.in_(
                    [str(g.target["mac_address"])]
                )
            )

    pairs = [
        aap_obj.AllowedAddressPair._load_object(context, db_obj)
        for db_obj in query.all()
    ]
    if len(pairs) > 0:
        msg = f"Address pairs dependency found for port: {g.target['id']}"
        LOG.info(msg)
        return Response(msg, status=403, mimetype="text/plain")

    LOG.info(f"Delete check passed for port: {g.target['id']}")
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
