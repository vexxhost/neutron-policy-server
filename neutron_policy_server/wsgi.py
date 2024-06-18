# SPDX-License-Identifier: Apache-2.0

import json
import sys

from flask import Flask, Response, request
from neutron.common import config
from neutron.db.models import allowed_address_pair as models
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron.objects.port.extensions import allowedaddresspairs as aap_obj
from neutron_lib import context
from neutron_lib.db import api as db_api

config.register_common_config_options()
config.init(sys.argv[1:])
config.setup_logging()

app = Flask(__name__)


def _fetch_context(request):
    content_type = request.headers.get(
        "Content-Type", "application/x-www-form-urlencoded"
    )
    if content_type == "application/x-www-form-urlencoded":
        data = request.form.to_dict()
        target = json.loads(data.get("target"))
        creds = json.loads(data.get("credentials"))
        rule = json.loads(data.get("rule"))
    elif content_type == "application/json":
        data = request.json
        target = data.get("target")
        creds = data.get("credentials")
        rule = data.get("rule")
    ctx = context.Context(user_id=creds["user_id"], project_id=creds["project_id"])
    return rule, target, ctx


# TODO(rlin): Only enable this after neutron bug/2069071 fixed.
# @app.route("/address-pair", methods=["POST"])
def enforce_address_pair():
    _, target, ctx = _fetch_context(request)
    # TODO(mnaser): Validate this logic, ideally we should limit this policy
    #               check only if its a provider network
    with db_api.CONTEXT_READER.using(ctx):
        network = network_obj.Network.get_object(ctx, id=target["network_id"])
    if network["shared"] is False:
        return Response("Not shared network", status=403, mimetype="text/plain")

    for allowed_address_pair in target.get("allowed_address_pairs", []):
        with db_api.CONTEXT_READER.using(ctx):
            ports = port_obj.Port.get_objects(
                ctx,
                network_id=target["network_id"],
                project_id=target["project_id"],
                mac_address=allowed_address_pair["mac_address"],
            )
        if len(ports) != 1:
            return Response(
                "Zero or Multiple match port found.", status=403, mimetype="text/plain"
            )
        fixed_ips = [str(fixed_ip["ip_address"]) for fixed_ip in ports[0].fixed_ips]
        if allowed_address_pair["ip_address"] not in fixed_ips:
            return Response(
                "IP address not exists in ports.", status=403, mimetype="text/plain"
            )
    return Response("True", status=200, mimetype="text/plain")


@app.route("/port-update", methods=["POST"])
def enforce_port_update():
    _, target, ctx = _fetch_context(request)
    if (
        "attributes_to_update" in target
        and ("mac_address" not in target["attributes_to_update"])
        and ("fixed_ips" not in target["attributes_to_update"])
    ):
        return Response("True", status=200, mimetype="text/plain")
    with db_api.CONTEXT_READER.using(ctx):
        ports = port_obj.Port.get_objects(ctx, id=target["id"])
        if len(ports) == 0:
            return Response("No match port found.", status=403, mimetype="text/plain")

        fixed_ips = [str(fixed_ip["ip_address"]) for fixed_ip in ports[0].fixed_ips]

        query = (
            ctx.session.query(models.AllowedAddressPair)
            .filter(
                models.AllowedAddressPair.mac_address.in_([str(ports[0].mac_address)])
            )
            .filter(models.AllowedAddressPair.ip_address.in_(fixed_ips))
        )
        pairs = query.all()
    pairs = [
        aap_obj.AllowedAddressPair._load_object(context, db_obj)
        for db_obj in query.all()
    ]
    if len(pairs) > 0:
        return Response(
            "Address pairs dependency found for this port.",
            status=403,
            mimetype="text/plain",
        )
    return Response("True", status=200, mimetype="text/plain")


@app.route("/port-delete", methods=["POST"])
def enforce_port_delete():
    _, target, ctx = _fetch_context(request)

    fixed_ips = [str(fixed_ip["ip_address"]) for fixed_ip in target["fixed_ips"]]
    with db_api.CONTEXT_READER.using(ctx):
        query = (
            ctx.session.query(models.AllowedAddressPair)
            .filter(
                models.AllowedAddressPair.mac_address.in_([str(target["mac_address"])])
            )
            .filter(models.AllowedAddressPair.ip_address.in_(fixed_ips))
        )

    pairs = query.all()
    pairs = [
        aap_obj.AllowedAddressPair._load_object(context, db_obj)
        for db_obj in query.all()
    ]
    if len(pairs) > 0:
        return Response(
            "Address pairs dependency found for this port.",
            status=403,
            mimetype="text/plain",
        )
    return Response("True", status=200, mimetype="text/plain")


def create_app():
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
