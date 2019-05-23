import logging
from urllib.parse import urlencode

from key import key, secretkey
from utils import dictargs, utcnow
import box
import certificate
import config
import order
import scope
import store
import username


class LogicException(Exception):
    pass


class UnknownRevokationPartyException(LogicException):
    pass


class ResourceException(LogicException):
    pass


class ResourceBadCertificateException(ResourceException):
    pass


class UnknownUserAuthzException(ResourceException):
    pass


class Base:
    def __init__(self, db_uri, sk_or_k):
        if isinstance(sk_or_k, secretkey):
            self.sk = sk_or_k
            self.k = self.sk.public()

        else:
            assert isinstance(sk_or_k, key)
            self.sk = None
            self.k = sk_or_k

        if db_uri is None:
            db_uri = 'sqlite:///:memory:'
        else:
            db_uri = db_uri.format(self.k)

        self.logger = logging.getLogger('alias').getChild(self.PREFIX)
        self.store = store.Store(db_uri, self.logger.getChild("store"))

        # XXX
        self.store.create_schema()

    # Transform code into token
    def from_token(self, code, **kwargs):
        return order.from_token(code, store=self.store, **kwargs)

    # Check order
    def check(self, o, **kwargs):
        return order.check(o, store=self.store, **kwargs)

    def store_token(self, code):
        """ Store token in local store. """
        o = self.from_token(code)
        self.store.store_order(o)

    # Sign order with root key
    def root_sign(self, o, **kwargs):
        assert self.sk, "secretkey not set"
        order.sign(o, sk=self.sk, store=self.store, **kwargs)
        assert order.root_signer(o) == self.k
        return o

    # Get a valid current subkey, or creates one lazily
    def subkey_order(self):
        subk_o = self.store.get_last_valid_subkey_order(self.k)

        # if no subkey were defined, generate one
        if subk_o is None:
            sub_sk = secretkey.default().generate()
            self.store.store_sk(sub_sk)
            sub_k = sub_sk.public()
            subk_o = order.new(
                order.ALIAS_SUBKEY,
                exp=config.SUBKEY_EXPIRES_IN,
                **sub_k.to_dict()
            )
            self.root_sign(subk_o)
            assert self.store.get_last_valid_subkey_order(self.k) == subk_o

            assert self.store.get_sk(sub_sk.public()) == sub_sk

        self.check(subk_o)
        return subk_o

    # Sign order with subkey
    def sign(self, o, **kwargs):
        subkey_k_o = self.subkey_order()
        subkey_k = key.from_dict(subkey_k_o)
        subkey_sk = self.store.get_sk(subkey_k)
        assert subkey_sk, f"no secret key for {subkey_k}"
        order.sign(o, sk=subkey_sk, k=subkey_k_o, store=self.store, **kwargs)
        assert order.root_signer(o) == self.k
        return o

    # generate a TLS token
    def tls_certificate(self, cert):
        algo = config.DEFAULT_HASH
        o = order.new(order.ALIAS_CERT,
                      finger=list(certificate.fingerprint(cert, algo)),
                      )

        now = utcnow().timestamp()
        naf = cert.not_valid_after.timestamp()
        self.sign(o, now=now, exp=naf - now)

        return order.to_token(o)

    # generate a revoke token
    def revoke(self, o, date=None):
        assert date is None, "TODO"
        assert order.signed(o)
        assert order.root_signer(o) == self.k

        o = order.new(order.ALIAS_REVOKE,
                      h=order.root_hash(o),
                      date=date,
                      )
        self.sign(o)

        return order.to_token(o)

    # called when a new revoke token is received
    def revoked(self, code):
        o = self.from_token(code)
        assert o["type"] == order.ALIAS_REVOKE
        revoking_party = order.root_signer(o)
        if not self.store.is_party_bound(revoking_party):
            raise UnknownRevokationPartyException()

        self.store.store_order(o)

    # called when a party just confirmed it received a revocation
    def confirm_revoked(self, oh, k):
        self.store.confirm_revoked(oh, k)

    def get_order(self, h, sess=None):
        sess = sess or self.store.session()
        return self.store.get_order(sess, h)

    def get_all_order(self, h, sess=None):
        sess = sess or self.store.session()
        return self.store.get_all_order(sess, h)

    def iter_all_orders(self):
        return self.store.iter_all_orders(self.k)

    def pending_revocations(self, **kwargs):
        return self.store.pending_revocations(self_k=self.k, **kwargs)


class BaseUserServer(Base):
    def __init__(self, domain, db_uri, sk):
        super().__init__(db_uri, sk)
        self.domain = domain

    @property
    def k_dict(self):
        k = self.k.to_dict()
        k['domain'] = self.domain
        return k

    # call when a BIND order is received
    def bound(self, code):
        o = self.from_token(code)
        assert o['type'] == order.ALIAS_BIND

        domain = o[self.PREFIX]['domain']
        assert domain == self.domain, f"order domain {domain!r} != real domain {self.domain}"

        self.store.store_order(o)


class User(Base):
    PREFIX = "user"

    def __init__(self, authz, *kargs, **kwargs):
        super().__init__(*kargs, **kwargs)
        self.authz = authz

    def sign(self, *kargs, **kwargs):
        o = super().sign(*kargs, **kwargs)
        self.store.store_order(o)
        return o

    def root_sign(self, *kargs, **kwargs):
        o = super().root_sign(*kargs, **kwargs)
        self.store.store_order(o)
        return o

    # User binds a domain and a resource server
    def bind(self, authz, rsrc):
        assert 'raw' in authz and 'alg' in authz and 'domain' in authz
        assert 'raw' in rsrc and 'alg' in rsrc and 'domain' in rsrc

        o = order.new(order.ALIAS_BIND,
                      rsrc=rsrc,
                      authz=authz,
                      )
        self.root_sign(o)

        return order.to_token(o)

    def authorize(self, args):
        assert args['response_type'] == 'code'

        client_o = self.from_token(args['client_id'])

        o = order.new(
            order.ALIAS_AUTHZ,
            client=client_o,
            redirect_uri=args['redirect_uri'],
            scopes=scope.split(args['scopes']),
            exp=config.DEFAULT_GRANT_TOKEN_TIMEOUT,
        )
        self.sign(o)

        return order.to_token(o)

    def get_rsrc_servers(self):
        r = {}
        for o in self.store.iter_user_resources(self.k, self.authz.k):
            k = str(key.from_dict(o['rsrc']))
            if k not in r:
                r[k] = dict(
                    domain=o['rsrc']['domain'],
                    order=o,
                    oh=order.root_hash(o),
                )

        return r

    def clients(self):
        clients = {}  # {client_k: {scope: {grant_oh: grant_o, ...}}}
        clients_o = {}  # {client_k: client_o}
        for o in self.store.iter_user_client_orders(self.k):
            if o['type'] == order.ALIAS_ACCESS:
                grant_o = o['grant']

            elif o['type'] == order.ALIAS_AUTHZ:
                grant_o = o

            elif o['type'] == order.ALIAS_REFRESH:
                grant_o = o['grant']

            else:
                raise Exception(f"unknown order {o['type']}")

            client_o = grant_o['client']
            client_k = order.root_signer(client_o)
            k = str(client_k)

            if k in clients_o:
                if order.sign_date(clients_o[k]) < order.sign_date(client_o):
                    clients_o.pop(k)

            if k not in clients_o:
                clients_o[k] = client_o

            scopes = clients.get(k)
            if scopes is None:
                scopes = clients[k] = {}

            for sc in grant_o['scopes']:
                grants = scopes.get(sc)
                if grants is None:
                    grants = scopes[sc] = {}

                oh = order.root_hash(grant_o)
                grants[oh] = grant_o

        return clients, clients_o


class Resource(BaseUserServer):
    PREFIX = "rsrc"

    def parse_access_token(self, code, crt_finger=None):
        o = self.from_token(code)
        assert o['type'] == order.ALIAS_ACCESS

        cert_o = o.get('cert')
        if cert_o:
            assert cert_o['type'] == order.ALIAS_CERT

            if crt_finger is None:
                raise ResourceBadCertificateException()

            assert crt_finger[0] == cert_o['finger'][0]
            if crt_finger[1] != cert_o['finger'][1]:
                raise ResourceBadCertificateException()

        # extract authz&client&user root keys and scopes
        authz_k = order.root_signer(o)
        user_k = order.root_signer(o['grant'])
        scopes = o['grant']['scopes']

        # check a valid bind certificate exists which binds all parties
        if not self.store.is_bound(user_k, authz_k, self.k):
            raise UnknownUserAuthzException()

        # client has the necessary credentials to access user's data over certain scopes
        return user_k, scopes


class Authorization(BaseUserServer):
    PREFIX = "authz"

    def token(self, grant_type, **kwargs):
        if grant_type == 'authorization_code':
            return self.token_authorization_code(**kwargs)

        # elif grant_type == 'refresh_token':
        #     return self.token_refresh_token(**kwargs)

        else:
            raise ValueError(f"unknown grant type: {grant_type!r}")

    def token_authorization_code(self, code, redirect_uri, client_id, cert=None):
        client_o = self.from_token(client_id)
        assert client_o['type'] == order.ALIAS_REGISTER
        client_k = order.root_signer(client_o)

        grant_o = self.from_token(code)
        assert grant_o['type'] == order.ALIAS_AUTHZ
        assert grant_o['redirect_uri'] == redirect_uri
        assert order.root_signer(grant_o['client']) == client_k

        cert_o = None
        if cert:
            cert_o = self.from_token(cert)
            assert order.root_signer(cert_o) == client_k

        # XXX re-use access token
        access_o = order.new(
            order.ALIAS_ACCESS,
            grant=grant_o,
            cert=cert_o,
            exp=config.DEFAULT_ACCESS_TOKEN_TIMEOUT,
        )
        self.sign(access_o)

        now = utcnow()
        expires_in = (order.expiration(access_o) - now).total_seconds()

        # XXX check bind was not expired?

        # get resource servers
        # XXX
        user_k = order.root_signer(grant_o)
        try:
            o = next(self.store.iter_user_resources(user_k, self.k))
        except StopIteration:
            # XXX no resource server bounded
            rsrcs = []
        else:
            rsrcs = [o['rsrc']['domain']]

        return dictargs(
            access_token=order.to_token(access_o),
            token_type="bearer",
            expires_in=expires_in,
            scopes=access_o['grant']['scopes'],
            refresh_token=code,
            rsrcs=rsrcs,
        )

    def parse_request(self, args):
        assert args['response_type'] == 'code'

        client_o = self.from_token(args['client_id'])
        scopes = scope.split(args['scopes'])

        return client_o, scopes


class Client(Base):
    PREFIX = "client"

    def __init__(self, db_uri, sk, **meta):
        assert 'redirect_uri' in meta

        super().__init__(db_uri, sk)

        self.meta = meta
        self.boxer = box.Boxer()

    def id(self):
        o = self.store.get_last_register(self.k)
        if not o:
            o = order.new(order.ALIAS_REGISTER, **self.meta)
            self.sign(o)
            assert self.store.get_last_register(self.k) == o

        return order.to_token(o)

    def authorize(self, alias, scopes, state=None):
        assert isinstance(scopes, (list, tuple))
        user, domain = username.parse(alias)
        state_o = self.boxer.encrypt(state) if state else None

        args = dictargs(
            alias=alias,
            client_id=self.id(),
            redirect_uri=self.meta['redirect_uri'],
            response_type='code',
            scopes=",".join(scopes),
            state=state_o,
        )

        url = f"{config.ALIAS_PROTO}://{domain}/alias/authorize?{urlencode(args)}"
        return url, args

    def token_req(self, authz_domain, code, crt_token=None):
        code_o = self.from_token(code)

        url = f"{config.ALIAS_PROTO}://{authz_domain}/alias/token"

        return url, dictargs(
            grant_type='authorization_code',
            code=code,
            redirect_uri=code_o.get('redirect_uri'),
            client_id=self.id(),
            cert=crt_token,
        )

#    def refresh_token_req(self, authz_domain, refresh_token, crt_token=None):
#        url = f"{config.ALIAS_PROTO}://{authz_domain}/alias/token"
#
#        return url, dictargs(
#            grant_type='refresh_token',
#            refresh_token=refresh_token,
#            cert=crt_token,
#        )
