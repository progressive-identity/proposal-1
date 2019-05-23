#!/usr/bin/env python3

from urllib.parse import urlencode
import base64
import datetime
import functools
import os
import pprint

from flask_cors import cross_origin
import flask
import requests

from utils import fromb64, tob64, dictargs, utcnow
from key import secretkey, key
import config
import logic
import order

import authz_worker

# Relative to Q&D user management
import pysodium as sodium
import store
from store import sql

DOMAIN = os.environ["ALIAS_DOMAIN"]

app = flask.Flask(
    __name__,
    template_folder="/templates",
    static_folder="/static",
)
authz = None


###

class UserAlreadyExistsException(Exception):
    pass


class UnknownUserException(Exception):
    pass


class User(store.Base):
    __tablename__ = 'user'

    id = sql.Column(sql.Integer, primary_key=True, nullable=False)
    alias = sql.Column(sql.String, unique=True, nullable=False)
    pwh = sql.Column(sql.String, nullable=False)
    sk = sql.Column(sql.String, nullable=False)

    @classmethod
    def create(cls, alias, pwh, sk=None):
        if not sk:
            sk = secretkey.default().generate()

        return cls(
            alias=alias,
            sk=str(sk),
            pwh=pwh,
        )

    def verify(self, pwd):
        if not sodium.crypto_pwhash_str_verify(self.pwh, pwd):
            raise UnknownUserException(self.alias)

    def user(self):
        sk = secretkey.from_str(self.sk)
        return logic.User(authz, os.environ.get("ALIAS_DB_URI"), sk)


class UserManager:
    @staticmethod
    def create(store, *kargs, **kwargs):
        sess = store.session()
        u = User.create(*kargs, **kwargs)
        sess.add(u)
        sess.commit()
        return u

    @staticmethod
    def open(store, alias, pwd):
        try:
            u = store.session().query(User).filter_by(alias=alias).one()

        except store.orm.exc.NoResultFound:
            return None

        else:
            u.verify(pwd)
            return u

    @staticmethod
    def get(store, alias):
        try:
            u = store.session().query(User).filter_by(alias=alias).one()

        except store.orm.exc.NoResultFound:
            return None

        else:
            return u


def session_set_user(u):
    flask.session["alias"] = u.alias


def session_current_user():
    if "alias" not in flask.session:
        return None

    alias = flask.session["alias"]
    return UserManager.get(authz.store, alias)


def session_logout():
    flask.session.pop("alias", None)


def logged(f):
    @functools.wraps(f)
    def wrapper(*kargs, **kwargs):
        u = session_current_user()

        if u is None:
            return flask.abort(403)

        return f(*kargs, **kwargs)
    return wrapper


def require_login(f):
    @functools.wraps(f)
    def wrapper(*kargs, **kwargs):
        u = session_current_user()

        if u is None:
            args = dict(redirect=flask.request.full_path)
            url = f"/alias/login?" + urlencode(args)
            return flask.redirect(url, code=302)

        return f(*kargs, **kwargs)
    return wrapper


def private(f):
    # XXX
    return f

###


@app.route("/alias/api/")
@cross_origin()
def api_index():
    return flask.jsonify(
        what="alias authorization server",
        k=str(authz.k),
    )


@app.route("/alias/api/create", methods=["POST"])
def api_create():
    if "pwh" not in flask.request.form:
        pwh = sodium.crypto_pwhash_str(
            flask.request.form["pwd"],
            # sodium.crypto_pwhash_OPSLIMIT_SENSITIVE,
            sodium.crypto_pwhash_OPSLIMIT_MIN,
            # sodium.crypto_pwhash_MEMLIMIT_SENSITIVE
            sodium.crypto_pwhash_MEMLIMIT_MIN
        ).decode('ascii')

    else:
        pwh = flask.request.form["pwh"]

    try:
        u = UserManager.create(authz.store, flask.request.form["name"], pwh, sk=None)

    except UserAlreadyExistsException:
        return flask.jsonify(
            status="error_user_already_exists",
        )

    else:
        session_set_user(u)
        return flask.jsonify(
            status="ok",
        )


@app.route("/alias/api/login", methods=["POST"])
def api_login():
    try:
        user = UserManager.open(authz.store, flask.request.form["name"], flask.request.form["pwd"])

    except UnknownUserException:
        return flask.jsonify(status="error", message="bad password or unknown user")

    else:
        session_set_user(user)
        return flask.jsonify(status="ok", user=user.alias)


@app.route("/alias/api/logout", methods=["POST"])
def api_logout():
    session_logout()
    return flask.jsonify(status="ok")


@app.route("/alias/api/bind_resource", methods=["POST"])
@logged
def api_bind_rsrc():
    u = session_current_user()
    assert u

    domain = flask.request.form['domain']

    # ping
    resp = requests.get(f"https://{domain}/alias/api/", verify=not config.DO_NOT_VERIFY_SSL)
    if not resp.ok:
        return flask.jsonify(state="error", error="unreachable domain")

    resp = resp.json()
    rsrc_k_dict = key.from_str(resp['k']).to_dict()
    rsrc_k_dict['domain'] = domain

    # Generate bind token
    bind_token = u.user().bind(authz.k_dict, rsrc_k_dict)

    # Send bind token
    args = dict(code=bind_token)
    resp = requests.post(
        f"https://{domain}/alias/api/bind/",
        data=args,
        verify=not config.DO_NOT_VERIFY_SSL,
    )
    if not resp.ok:
        return flask.jsonify(state="error", error="bind failed"), 500

    authz.bound(bind_token)
    return flask.jsonify(state="success")


@app.route("/alias/api/debug/")
def api_debug():
    r = authz_worker.ping.delay()
    return flask.jsonify(r=repr(r))


@app.route("/alias/api/debug/dump/")
def api_debug_dump():
    r = dict(authz=authz.store.dump())
    u = session_current_user()
    r['user'] = u.user().store.dump() if u else None
    return flask.Response(pprint.pformat(r), content_type="text/plain")


@app.route("/alias/api/revoke/", methods=["POST"])
@logged
def api_revoke():
    u = session_current_user()
    assert u
    user = u.user()

    # hash of order to revoke
    ohb64 = flask.request.form['oh']
    oh = fromb64(ohb64)
    o = user.get_order(oh)
    if o is None:
        return flask.jsonify(status="error", error="order not found"), 404

    # generate revoke order
    code = user.revoke(o)
    authz.store.store_order(authz.from_token(code))

    # broadcast revocations XXX
    r = authz.pending_revocations()
    print(r, flush=True)
    q = []
    for h, v in r.items():
        for k, domain in v['servers'].items():
            q.append(dict(
                h=tob64(h),
                code=v['code'],
                k=str(k),
                domain=domain
            ))
    authz_worker.broadcast_revocations.delay(q)

    return flask.jsonify(status="ok", code=code)


@app.route("/alias/api/revoked/", methods=["POST"])
def api_revoked():
    code = flask.request.form["code"]
    try:
        authz.revoked(code)

    except logic.UnknownRevokationPartyException:
        return flask.jsonify(state="error", error="unknown revokation party"), 400

    else:
        return flask.jsonify(state="ok")


@app.route("/alias/api/confirm_revoked/", methods=["POST"])
@private
def api_confirm_revoked():
    k = key.from_str(flask.request.form["k"])
    oh = fromb64(flask.request.form["oh"])

    authz.confirm_revoked(oh, k)

    return flask.jsonify(state="ok")


@app.route("/alias/api/revocations/")
def api_revocations():
    r = authz.pending_revocations()

    q = []
    for h, v in r.items():
        for k, domain in v['servers'].items():
            q.append(dict(
                h=tob64(h),
                code=v['code'],
                k=str(k),
                domain=domain
            ))

    return flask.jsonify(r=q)

###


@app.route('/alias/static/<path:path>')
def route_static(path):
    return flask.send_from_directory(app.static_folder, path)


@app.route('/')
@app.route('/alias')
@require_login
def index():
    now = utcnow()

    u = session_current_user()
    user = u.user()

    rsrc_servers = user.get_rsrc_servers()
    clients, clients_o = user.clients()

    all_orders = []
    for o, exp in user.iter_all_orders():
        e = dict(
            oh=order.root_hash(o),
            type=o['type'],
            date=datetime.datetime.utcfromtimestamp(o['_sig']['dat']),
        )

        e['exp'] = exp
        e['expired'] = now >= exp if exp else False

        all_orders.append(e)

    return flask.render_template(
        'authz_index.html',
        DOMAIN=DOMAIN,
        all_orders=all_orders,
        clients=clients,
        clients_o=clients_o,
        enumerate=enumerate,
        rsrc_servers=rsrc_servers,
        sorted=sorted,
        tob64=tob64,
        user=u,
        user_k=str(user.k),
    )


@app.route("/alias/login", methods=["GET", "POST"])
def login():
    login_status = None
    if flask.request.method == "POST":
        try:
            user = UserManager.open(authz.store, flask.request.form["name"], flask.request.form["pwd"])

        except UnknownUserException:
            login_status = "error: bad password or unknown user"

        else:
            session_set_user(user)
            login_status = "You're logged in."

            redirect_url = flask.request.args.get("redirect", "/alias")
            if redirect_url:
                return flask.redirect(redirect_url, code=302)

    return flask.render_template("authz_login.html",
                                 DOMAIN=DOMAIN,
                                 alias=flask.request.args.get("alias"),
                                 login_status=login_status,
                                 )


@app.route("/alias/logout")
def logout():
    session_logout()
    return flask.redirect("/alias/login", code=302)


@app.route("/alias/authorize", methods=['GET', 'POST'])
def authorize():
    # XXX redirect to client when an error happens (malformed request, ...)

    state = flask.request.args.get('state')
    alias = flask.request.args.get("alias")

    def redirect(**kwargs):
        args = dictargs(**kwargs)
        url = f"{redirect_uri}?{urlencode(args)}"
        return flask.redirect(url, code=302)

    def redirect_error(error, desc=None, uri=None):
        return redirect(error=error, error_description=desc, error_uri=uri)

    redirect_uri = flask.request.args.get('redirect_uri')
    if redirect_uri is None:
        return redirect_error("invalid_request", "missing argument 'redirect_uri'")

    try:
        client_o, scopes = authz.parse_request(flask.request.args)
    except Exception:   # XXX what exceptions?
        return redirect_error("invalid_request")

    if client_o['redirect_uri'] != redirect_uri:
        return redirect_error("invalid_request", "bad redirect uri")

    u = session_current_user()
    if u is None:
        args = dictargs(redirect=flask.request.full_path, alias=alias)
        url = f"/alias/login?" + urlencode(args)
        return flask.redirect(url, code=302)

    if flask.request.method == 'POST':
        agree = flask.request.form.get("agree") == "y"
        deny = flask.request.form.get("deny") == "y"
        assert agree != deny

        if not agree:
            return redirect(error="access_denied")

        grant_code = u.user().authorize(flask.request.args)
        return redirect(code=grant_code, state=state)

    return flask.render_template("authz_authorize.html",
                                 client=client_o,
                                 scopes=sorted(scopes),
                                 alias=alias,
                                 pformat=pprint.pformat,
                                 )


@app.route('/alias/token', methods=['POST'])
def token():
    if flask.request.form.get('grant_type') != 'authorization_code':
        return flask.jsonify(state="error", reason="bad arguments"), 400

    try:
        token_resp = authz.token(**flask.request.form)

    except order.BaseException as e:
        return flask.jsonify(error=e.REASON)

    return flask.jsonify(**token_resp)


@app.route("/alias/order/<ohb64>")
@require_login
def get_order(ohb64):
    now = utcnow()

    u = session_current_user()
    user = u.user()

    oh = fromb64(ohb64)
    o_m = user.get_all_order(oh)
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

    return flask.render_template('order.html',
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
    global authz

    import utils
    utils.prepare_log()

    sk = secretkey.from_str(os.environ["ALIAS_SK"])
    authz = logic.Authorization(
        os.environ["ALIAS_DOMAIN"],
        os.environ.get("ALIAS_DB_URI"),
        sk,
    )

    app.secret_key = base64.b64decode(os.environ["FLASK_SECRET_KEY"].encode('utf-8'))

    app.run(host="0.0.0.0", port=80)


if __name__ == '__main__':
    run()
