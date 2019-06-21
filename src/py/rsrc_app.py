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
import order
import indexer

DOMAIN = os.environ["ALIAS_DOMAIN"]

app = flask.Flask(
    __name__,
    template_folder="/templates",
    static_folder="/static",
)

rsrc = None


@app.route('/alias/static/<path:path>')
def route_static(path):
    return flask.send_from_directory(app.static_folder, path)


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


def get_dirname(user_k):
    return str(user_k)


def get_crt_hash():
    crt_hash = flask.request.headers.get("X-Alias-Clientcert-Sha256")
    if crt_hash:
        crt_hash = ("sha256", base64.urlsafe_b64decode(crt_hash))

    return crt_hash


@app.route('/alias/resource/')
def providers():
    code = flask.request.args.get('code')
    if not code:
        return flask.abort(400)

    try:
        user_root_k, scopes = rsrc.parse_access_token(code, get_crt_hash())

    except logic.ResourceException:
        return flask.abort(404)

    except order.BaseException:
        return flask.abort(404)

    rsrc_path = os.path.join("/rsrc", get_dirname(user_root_k))
    authz_providers = index.query_provider(rsrc_path, scopes)

    return flask.jsonify(providers=authz_providers)


@app.route('/alias/resource/<provider>')
def resource(provider):
    code = flask.request.args.get('code')
    if not code:
        return flask.abort(400)

    try:
        user_root_k, scopes = rsrc.parse_access_token(code, get_crt_hash())

    except logic.ResourceException:
        return flask.abort(404)

    except order.BaseException:
        return flask.abort(404)

    provider_path = os.path.join("/rsrc", get_dirname(user_root_k), provider)

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


@app.route('/alias/resource/<provider>/<hhuman>')
def query_blob(provider, hhuman):
    code = flask.request.args.get('code')
    if not code:
        return flask.abort(400)

    try:
        user_root_k, scopes = rsrc.parse_access_token(code, get_crt_hash())

    except logic.ResourceException:
        return flask.abort(404)

    except order.BaseException:
        return flask.abort(404)

    hashname, hb64 = hhuman.split('_', 1)
    h = base64.urlsafe_b64decode(hb64)

    provider_path = os.path.join("/rsrc", get_dirname(user_root_k), provider)
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

# Upload & Indexing


@app.route('/alias/upload/')
def upload():
    return flask.render_template('rsrc_upload.html')


@app.route("/alias/upload/process/", methods=["POST"])
def upload_process():
    urls = flask.request.form.getlist('urls[]')

    uploads = []
    for url in urls:
        _, upload_id = url.rsplit('/', 1)
        if not upload_id:
            return flask.abort(400)

        upload_path = os.path.join("/upload", upload_id)
        upload_info_path = upload_path + ".info"
        upload_bin_path = upload_path + ".bin"

        if not os.path.exists(upload_info_path) or not os.path.exists(upload_bin_path):
            return flask.abort(400)

        with open(upload_info_path, "r") as fh:
            upload_info = json.load(fh)

        uploads.append(upload_info)

    # XXX TODO user
    # XXX TODO provider
    r = indexer.index("gawen", "google", uploads)

    return flask.jsonify(**r)


@app.route("/alias/upload/process/<id>")
def upload_process_id(id):
    state = indexer.status(id)
    if state is None:
        return flask.abort(404)

    return flask.jsonify(**state)


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
