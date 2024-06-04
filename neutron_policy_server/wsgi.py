# SPDX-License-Identifier: Apache-2.0

import sys

from flask import Flask, Response, request
from neutron.common import config
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron_lib import context
from neutron_lib.db import api as db_api

config.register_common_config_options()
config.init(sys.argv[1:])
config.setup_logging()

app = Flask(__name__)


@app.route("/enforce", methods=["POST"])
def enforce():
    data = request.json
    rule = data.get("rule")
    target = data.get("target")
    creds = data.get("creds")

    ctx = context.Context(user_id=creds["user_id"], project_id=creds["project_id"])

    if rule == "create_port:allowed_address_pairs":
        # TODO(mnaser): Validate this logic, ideally we should limit this policy
        #               check only if its a provider network
        with db_api.CONTEXT_READER.using(ctx):
            network = network_obj.Network.get_object(ctx, id=target["network_id"])
        if network["shared"] is False:
            return Response(status=403)

        for allowed_address_pair in target.get("allowed_address_pairs", []):
            with db_api.CONTEXT_READER.using(ctx):
                ports = port_obj.Port.get_objects(
                    ctx,
                    network_id=target["network_id"],
                    project_id=target["project_id"],
                    mac_address=allowed_address_pair["mac_address"],
                )

            if len(ports) != 1:
                return Response(status=403)

            fixed_ips = [str(fixed_ip["ip_address"]) for fixed_ip in ports[0].fixed_ips]
            if allowed_address_pair["ip_address"] not in fixed_ips:
                return Response(status=403)

        return Response(status=200)


def create_app():
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
