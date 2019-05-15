#!/usr/bin/env python3

import base64
import datetime
import json
import os
import re

import flask
from flask_cors import cross_origin

from key import secretkey
import logic
import index

DOMAIN = os.environ["ALIAS_DOMAIN"]

app = flask.Flask(
    __name__,
)

rsrc = None


@app.route("/alias/api/")
@cross_origin()
def api_index():
    return flask.jsonify(
        what="alias resource server",
        k=str(rsrc.k),
    )


@app.route("/alias/api/debug/dump")
def api_dump():
    from pprint import pformat
    return flask.Response(pformat(rsrc.store.dump()), content_type="text/plain")


@app.route("/alias/api/debug")
def api_debug():
    return flask.jsonify(headers=dict(flask.request.headers))

###


def parse_args(args):
    if not args:
        return {}

    d = {}
    args = args.split(',')

    for arg in args:
        k, v = arg.split('=', 1)
        d[k] = v

    return d


def parse_scope(scope):
    RE = re.compile(r"^(?P<scope>[a-zA-Z\.]+)(\[(?P<args>[a-zA-Z0-9,=&|\(\)]+)\])?$")

    m = RE.match(scope)

    if not m:
        raise Exception("bad scope")

    m = m.groupdict()
    args = parse_args(m['args'])

    return m['scope'], args


def match_meta(meta, args):
    for k, v in args.items():
        if k not in meta or meta[k] != v:
            return False

    return True


@app.route('/alias/api/bind/', methods=['POST'])
def api_bind():
    code = flask.request.form['code']
    rsrc.bound(code)

    return flask.jsonify(state="success")


@app.route("/alias/api/revoked/", methods=["POST"])
def api_revoked():
    code = flask.request.form["code"]
    try:
        rsrc.revoked(code)

    except Exception:
        import traceback
        print(traceback.format_exc(), flush=True)

    # except logic.UnknownRevokationPartyException:
    #    return flask.jsonify(state="error", error="unknown revokation party"), 400

    else:
        return flask.jsonify(state="ok")


@app.route('/alias/resource/<provider>')
def resource(provider):
    code = flask.request.args.get('code')
    if not code:
        return flask.abort(400)

    # XXX
    crt_hash = None

    try:
        user_root_k, scopes = rsrc.parse_access_token(code, crt_hash)

    except logic.ResourceException:
        return flask.abort(404)

    user = str(user_root_k)
    provider_path = os.path.join("/rsrc", user, provider)

    def json_default(v):
        if isinstance(v, datetime.datetime):
            return v.isoformat()

        elif isinstance(v, index.File):
            hhuman = base64.urlsafe_b64encode(v._hash).decode('ascii')
            rsrc_name = f"{v.hashname}_{hhuman}"
            return f"/alias/resource/{provider}/{rsrc_name}"

    def generate():
        yield '['
        first = True
        for scope, obj in index.query(provider_path, scopes):
            if not first:
                yield ','
            obj['scope'] = scope
            yield json.dumps(obj, default=json_default)
            first = False
        yield ']'

    return flask.Response(generate(), mimetype='application/json')


@app.route('/alias/<provider>/<hhuman>')
def query_blob(provider, hhuman):
    code = flask.request.args.get('code')
    if not code:
        return flask.abort(400)

    # XXX
    crt_hash = None

    try:
        user_root_k, scopes = rsrc.parse_access_token(code, crt_hash)

    except logic.ResourceException:
        return flask.abort(404)

    user = str(user_root_k)

    hashname, hb64 = hhuman.split('_', 1)
    h = base64.urlsafe_b64decode(hb64)

    provider_path = os.path.join("/rsrc", user, provider)
    blob = index.query_blob(provider_path, scopes, hashname, h)

    if blob:
        mimetype = blob.mimetype or blob.guess_mimetype()[0]

        def generate(chunk_size):
            path = blob.path.replace(f'/alias/{provider}', provider_path)
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(chunk_size)

                    if not chunk:
                        break

                    yield chunk

        return flask.Response(generate(64 * 1024), mimetype=mimetype)

    else:
        return flask.abort(404)


def run():
    global rsrc

    import utils
    utils.prepare_log()

    sk = secretkey.from_str(os.environ["ALIAS_SK"])
    rsrc = logic.Resource(
        os.environ["ALIAS_DOMAIN"],
        os.environ.get("ALIAS_DB_URI"),
        sk,
    )

    app.secret_key = base64.b64decode(os.environ["FLASK_SECRET_KEY"].encode('utf-8'))

    app.run(host="0.0.0.0", port=80)


if __name__ == '__main__':
    run()
