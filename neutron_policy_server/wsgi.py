# SPDX-License-Identifier: Apache-2.0

"""HTTP policy server, called by neutron through oslo.policy ``http:`` rules.

The decisions live in :mod:`neutron_policy_server.policies`; this module only
translates HTTP requests into calls to them.
"""

import json
import sys

from flask import Flask, Response, g, request
from neutron.common import config
from neutron.objects import ports as port_obj
from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_log import log as logging

from neutron_policy_server import policies

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
    g.ctx = policies.context_from_creds(g.creds)


def _strict():
    # Check only IP address if strict is 0
    return bool(request.args.get("strict", default=1, type=int))


def _respond(decision):
    status = 200 if decision.allowed else 403
    return Response(decision.message, status=status, mimetype="text/plain")


@app.route("/address-pair", methods=["POST"])
def enforce_address_pair():
    return _respond(policies.address_pair(g.ctx, g.target, strict=_strict()))


@app.route("/port-update", methods=["POST"])
def enforce_port_update():
    return _respond(policies.port_update(g.ctx, g.target, strict=_strict()))


@app.route("/port-delete", methods=["POST"])
def enforce_port_delete():
    return _respond(policies.port_delete(g.ctx, g.target, strict=_strict()))


@app.route("/health", methods=["GET"])
def health_check():
    with db_api.CONTEXT_READER.using(g.ctx):
        port_obj.Port.get_objects(g.ctx, id=["neutron_policy_server_health_check"])
        return Response(status=200)


def create_app():
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=9697)
