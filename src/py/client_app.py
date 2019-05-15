#!/usr/bin/env python3

import os
import base64
import functools
from urllib.parse import urlencode

import flask
import requests

from utils import *
from key import key, secretkey
import logic
import config

app = flask.Flask(
    __name__,
    template_folder="/templates",
    static_folder="/static",
)
client = None

DOMAIN = os.environ["ALIAS_DOMAIN"]
REDIRECT_URI = f"{config.ALIAS_PROTO}://{DOMAIN}/alias/cb"

@app.route("/")
def index():
    return flask.render_template("client_index.html",
        meta = client.meta,
        ALIAS_PROTO = config.ALIAS_PROTO
    )

@app.route("/alias/api/debug/dump")
def api_get_debug():
    from pprint import pformat
    return flask.Response(pformat(client.store.dump()), content_type="text/plain")

@app.route("/alias/authorize")
def authorize():
    name = flask.request.args["name"]
    domain = flask.request.args["domain"]
    scopes = flask.request.args["scopes"]
    redirect = flask.request.args.get("redirect")
    alias = flask.request.args.get("alias")

    state = dictargs(
        authz_domain = domain
    )
    request_args = client.request_args(scopes, alias=alias, state=state)
    args = urlencode(request_args)
    url = f"{config.ALIAS_PROTO}://{domain}/alias/authorize?{args}"

    return flask.redirect(url, code=302)


@app.route("/alias/cb")
def cb():
    error = flask.request.args.get('error')
    if error:
        desc = flask.request.args.get('error_description')
        uri = flask.request.args.get('error_uri')

        return flask.render_template('client_cb_error.html',
            desc = desc,
            error = error,
            uri = uri
        )

    code = flask.request.args["code"]
    state = client.boxer.decrypt(flask.request.args["state"])
    token_url = f"{config.ALIAS_PROTO}://{state['authz_domain']}/alias/token"
    token_args = client.token_args(code)

    resp = requests.post(token_url, data=token_args)
    print(resp.text)
    resp_j = resp.json()

    rsrc_domain = resp_j['rsrcs'][0]
    rsrc_url = f"{config.ALIAS_PROTO}://{rsrc_domain}/alias/resource"
    access_token = resp_j['access_token']
    args = dict(code=access_token)

    url = f"{rsrc_url}?{urlencode(args)}"

    return flask.jsonify(
        base_url = rsrc_url,
        access_token = access_token,
        url = url,
    )

def run():
    global client

    import utils; utils.prepare_log()

    sk = secretkey.from_str(os.environ["ALIAS_SK"])
    client = logic.Client(
        os.environ.get("ALIAS_DB_URI"),
        sk,
        desc = "A description for a sample alias client for demoing the Alias protocol.",
        name = "Sample Alias client",
        redirect_uri = REDIRECT_URI,
    )

    app.secret_key = base64.b64decode(os.environ["FLASK_SECRET_KEY"].encode('utf-8'))

    app.run(host="0.0.0.0", port=80)

if __name__ == '__main__':
    run()

