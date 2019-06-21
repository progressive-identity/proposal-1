#!/usr/bin/env python3

from urllib.parse import urlencode
import base64
import datetime
import json
import os
import pprint
import re
import tempfile

import flask
import flask_session
import requests
import redis

from key import secretkey, key
from utils import dictargs, tob64, utcnow, fromb64
import certificate
import config
import logic
import order
import scope
import username

app = flask.Flask(
    __name__,
    template_folder="/templates",
    static_folder="/static",
)
app.secret_key = base64.b64decode(os.environ["FLASK_SECRET_KEY"].encode('utf-8'))
client = None

DOMAIN = os.environ["ALIAS_DOMAIN"]
REDIRECT_URI = f"{config.ALIAS_PROTO}://{DOMAIN}/alias/cb"

# Redis session
SESSION_TYPE = "redis"
SESSION_REDIS = redis.Redis(host="redis.client.gdpr.dev.local")
app.config.from_object(__name__)
flask_session.Session(app)


@app.route("/")
def index():
    if "grant" in flask.session:
        items = flask.session["grant"].items()
        grants = sorted(items, key=lambda k_v: k_v[1]['date'], reverse=True)

    else:
        grants = None

    return flask.render_template(
        "client_index.html",
        meta=client.meta,
        grants=grants,
    )


@app.route("/clear_grants", methods=['POST'])
def clear_grants():
    if 'grant' in flask.session:
        flask.session.pop('grant')
        flask.session.modified = True

    return flask.jsonify(state="ok")


@app.route("/grant", methods=['POST'])
def post_grant():
    name = flask.request.form['name']
    scopes = flask.request.form['scopes']

    user, domain = username.parse(name)

    # Test authz server is online
    test_url = f"{config.ALIAS_PROTO}://{domain}/alias/api/"
    r = requests.get(test_url)

    if not r.ok:
        return flask.jsonify(
            state="error",
            reason="could not reach authorization server"
        )

    r = r.json()
    if r.get('what') != "alias authorization server":
        return flask.jsonify(
            state="error",
            reason="not an alias authorization server"
        )

    state = dictargs(
        alias=dict(user=user, domain=domain),
    )
    url, _ = client.authorize(name, scopes, state=state)
    return flask.jsonify(
        state="ok",
        url=url,
    )


def get_grant(grant_k):
    if 'grant' not in flask.session:
        return flask.abort(404)

    grant = flask.session['grant'].get(grant_k)
    if grant is None:
        return flask.abort(404)

    return grant


@app.route("/grant/<grant_k>/")
def grant_index(grant_k):
    get_grant(grant_k)  # for error if grant doesn't exist

    return flask.render_template(
        "client_grant_index.html",
        k=grant_k,
    )


@app.route("/grant/<grant_k>/resource")
def grant_index_resource(grant_k):
    path = flask.request.args.get('path')
    grant = get_grant(grant_k)  # for error if grant doesn't exist

    if grant.get('rsrcs') is None or grant.get('crt') is None or grant.get('sk') is None:
        return flask.abort(404)

    if len(grant['rsrcs']) == 0:
        return "No resource server defined"

    rsrc = grant['rsrcs'][0]

    def request(method, path, **kwargs):
        with tempfile.NamedTemporaryFile(mode='w+') as crt_fh:
            with tempfile.NamedTemporaryFile(mode='w+') as sk_fh:
                crt_fh.write(grant['crt'])
                crt_fh.flush()

                sk_fh.write(grant['sk'])
                sk_fh.flush()

                cert = (crt_fh.name, sk_fh.name)
                args = dict(
                    code=grant['access_token'],
                )
                url = f"https://{rsrc}/alias/resource/{path}?{urlencode(args)}"

                return requests.request(
                    method,
                    url,
                    cert=cert,
                    verify=not config.DO_NOT_VERIFY_SSL,
                    **kwargs
                )

    if path is None:
        r = request("GET", "")
        if not r.ok:
            return f"<h3>Error</h3><p>Resource server returned {r.status_code}</p>"

        def generate(r):
            yield "<h3>Providers</h3>"
            yield "<ul>"
            for provider in sorted(r['providers']):
                args = dict(path=provider)
                yield f'<li><a href="/grant/{grant_k}/resource?{urlencode(args)}">{provider}</a></li>'
            yield "</ul>"

        r = r.json()
        return flask.Response(generate(r))

    r = request("GET", path)
    if not r.ok:
        return f"<h3>Error</h3><p>Resource server returned {r.status_code}</p>"

    mimetype = r.headers.get("Content-Type", "text/html")

    if mimetype == "application/json":
        def match_to_link(m):
            orig = m.string[m.start():m.end()]
            path = m.groupdict()['path']
            args = dict(path=path)
            return f'<a href="/grant/{grant_k}/resource?{urlencode(args)}">{orig}</a>'

        def generate(r):
            yield f"<h3>Provider {path}</h3>"
            yield "<pre>"
            r = json.dumps(r, indent=4)
            yield re.sub(
                r'\"\/alias\/resource\/(?P<path>[^\"]+)\"',
                match_to_link,
                r
            )
            yield "</pre>"

        r = r.json()
        return flask.Response(generate(r))

    return flask.Response(r.content, mimetype=mimetype)


def json_from_token(code):
    if code is None:
        return None

    o = client.from_token(code, auto_check=False)

    try:
        client.check(o)

    except order.BaseException as e:
        valid = (False, str(e))

    else:
        valid = (True, )

    return dict(
        code=code,
        date=str(order.sign_date(o)),
        expiration=str(order.expiration(o)),
        oh=tob64(order.root_hash(o)),
        root_signer=str(order.root_signer(o)),
        valid=valid,
    )


@app.route("/grant/<grant_k>/json")
def grant_index_json(grant_k):
    grant = get_grant(grant_k)

    grant_o = client.from_token(grant['grant_token'], auto_check=False)

    r = dict(
        grant=json_from_token(grant['grant_token']),
        access=json_from_token(grant.get('access_token')),
        refresh=json_from_token(grant.get('refresh_token')),
        scopes=grant_o['scopes'],
        alias=grant['alias'],
        crt=grant.get('crt'),
    )

    return flask.jsonify(**r)


@app.route("/grant/<grant_k>/tokens", methods=['POST'])
def get_tokens(grant_k):
    grant = get_grant(grant_k)

    access_token = grant.get('access_token')

    try:
        if access_token:
            raise NotImplementedError    # XXX

        else:
            # generate TLS client certificate
            crt, sk = certificate.generate(datetime.timedelta(days=365.25))
            grant["crt"] = certificate.to_pem(crt)
            grant["sk"] = certificate.sk_to_pem(sk)

            # get first access & refresh tokens
            crt_token = client.tls_certificate(crt)
            url, args = client.token_req(
                grant['alias']['domain'],
                grant['grant_token'],
                crt_token=crt_token,
            )

            r = requests.post(url, data=args)
            if not r.ok:
                return flask.jsonify(
                    state="error",
                    reason="could not reach authorization server"
                )

            r = r.json()

            if 'error' in r:
                return flask.jsonify(
                    state='error',
                    reason=r['error']
                )

    except order.BaseException as e:
        return flask.jsonify(
            state="error",
            reason=str(e)
        )

    else:
        access_token = r.get('access_token')
        if access_token is not None:
            grant["access_token"] = access_token

        grant["rsrcs"] = r["rsrcs"]

        flask.session.modified = True

        return flask.jsonify(
            state="ok",
        )


@app.route("/alias/api/debug/dump")
def api_get_debug():
    from pprint import pformat
    return flask.Response(pformat(client.store.dump()), content_type="text/plain")


@app.route("/alias/cb")
def cb():
    state = flask.request.args.get('state')
    error = flask.request.args.get('error')
    if error:
        desc = flask.request.args.get('error_description')
        uri = flask.request.args.get('error_uri')

        return flask.render_template('client_cb_error.html',
                                     desc=desc,
                                     error=error,
                                     uri=uri
                                     )

    code = flask.request.args["code"]
    state = client.boxer.decrypt(state) if state else None

    grant_o = client.from_token(code)
    k = tob64(order.root_hash(grant_o))

    if 'grant' not in flask.session:
        flask.session['grant'] = {}

    flask.session['grant'][k] = dict(
        grant_o=grant_o,
        date=order.sign_date(grant_o),
        grant_token=code,
        alias=state['alias'],
    )

    flask.session.modified = True

    return flask.redirect(f"/grant/{k}/", code=302)


@app.route("/alias/order/<ohb64>/")
def get_order(ohb64):
    now = utcnow()

    oh = fromb64(ohb64)
    o_m = client.get_all_order(oh)

    if not o_m:
        return flask.abort(404)

    o, m = o_m
    exp = m['expiration']
    revocation_date = m['revocation_date']
    expired = exp and now >= exp
    revoked = revocation_date and now >= revocation_date

    signer = order.root_signer(o)
    date = datetime.datetime.utcfromtimestamp(o['_sig']['dat'])

    def indent(i):
        return '  ' * i

    def pretty(o, idt=0):
        is_root = idt == 0

        if is_root:
            o = dict(o)
            o.pop('_sig')

        if isinstance(o, (list, tuple)):
            yield '[\n'
            for i in o:
                yield indent(idt + 1)
                yield from pretty(i, idt + 1)
                yield ",\n"
            yield indent(idt) + ']'

        elif isinstance(o, dict):
            if order.signed(o) and not is_root:
                ohb64 = tob64(order.root_hash(o))
                yield f'<a href="/alias/order/{ohb64}">order <code>{ohb64}</code></a>'

            else:
                yield '{\n'
                for k, v in o.items():
                    yield indent(idt + 1) + repr(k) + ': '
                    yield from pretty(v, idt + 1)
                    yield ",\n"
                yield indent(idt) + '}'

        else:
            yield flask.escape(repr(o))

    pretty_o = flask.Markup("".join(pretty(o)))

    return flask.render_template(
        'order.html',
        date=date,
        exp=exp,
        expired=expired,
        key=key,
        o=o,
        ohb64=ohb64,
        order=order,
        pformat=pprint.pformat,
        pretty_o=pretty_o,
        revocation_date=revocation_date,
        revoked=revoked,
        signer=signer,
        sorted=sorted,
        tob64=tob64,
    )


def run():
    global client

    import utils
    utils.prepare_log()

    sk = secretkey.from_str(os.environ["ALIAS_SK"])
    client = logic.Client(
        os.environ.get("ALIAS_DB_URI"),
        sk,
        desc="Access Alias resources",
        name="Alias Explorer",
        redirect_uri=REDIRECT_URI,
    )

    app.run(host="0.0.0.0", port=80)


if __name__ == '__main__':
    run()
