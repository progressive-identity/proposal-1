from collections import defaultdict
import hashlib
import datetime
import logging

import sqlalchemy as sql
import sqlalchemy.orm as orm
import sqlalchemy.ext.declarative

from utils import tob64
from key import key, secretkey
import order

class BaseException(Exception):
    pass

class UnknownOrderException(BaseException):
    pass

Base = sqlalchemy.ext.declarative.declarative_base()

class sql_Key(sql.types.TypeDecorator):
    impl = sql.types.String

    def process_bind_param(self, value, dialect):
        if value is not None:
            assert isinstance(value, key)
            value = str(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = key.from_str(value)
        return value

class sql_SecretKey(sql.types.TypeDecorator):
    impl = sql.types.String

    def process_bind_param(self, value, dialect):
        if value is not None:
            assert isinstance(value, secretkey)
            value = str(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = secretkey.from_str(value)
        return value

HASH_SIZE = hashlib.sha256().digest_size
TYPE_MAXLEN = 32
class Order(Base):
    __tablename__ = 'order'

    id = sql.Column(sql.Integer, primary_key=True, nullable=False)
    h = sql.Column(sql.String(HASH_SIZE), unique=True, nullable=False)
    raw = sql.Column(sql.Binary(), unique=True, nullable=False)
    type = sql.Column(sql.String(TYPE_MAXLEN), nullable=False)

    # Root signer of the order. NULL if not signed.
    root_signer = sql.Column(sql_Key(), nullable=True)

    # Signature date of the order.
    sign_date = sql.Column(sql.DateTime(), nullable=False)

    # Order's expiration
    expiration = sql.Column(sql.DateTime(), nullable=True)

    # Order's revocation date, if revoked
    revocation_date = sql.Column(sql.DateTime(), nullable=True)

    # User ultimately linked
    user_k = sql.Column(sql_Key(), nullable=True)

    bind = orm.relationship("Bind", uselist=False, back_populates="order")
    revocation = orm.relationship("Revocation", uselist=False, back_populates="order")
    revocation_confirms = orm.relationship("RevocationConfirm", back_populates="revoke_order")

def order_from_sql(o_sql):
    return order.from_raw(o_sql.raw)

class Key(Base):
    __tablename__ = 'key'

    id = sql.Column(sql.Integer, primary_key=True, nullable=False)
    k = sql.Column(sql_Key(), nullable=False)
    sk = sql.Column(sql_SecretKey(), nullable=False)

class Bind(Base):
    __tablename__ = 'bind'

    id = sql.Column(sql.Integer, sql.ForeignKey("order.id"), primary_key=True, nullable=False)
    order = orm.relationship("Order", back_populates="bind")
    authz_k = sql.Column(sql_Key(), nullable=False)
    rsrc_k = sql.Column(sql_Key(), nullable=False)
    authz_domain = sql.Column(sql.String(), nullable=False)
    rsrc_domain = sql.Column(sql.String(), nullable=False)

class Revocation(Base):
    __tablename__ = 'revocation'

    id = sql.Column(sql.Integer, sql.ForeignKey("order.id"), primary_key=True, nullable=False)
    order = orm.relationship("Order", back_populates="revocation")
    h = sql.Column(sql.String(HASH_SIZE), nullable=False, unique=True)

class RevocationConfirm(Base):
    __tablename__ = 'revocation_confirm'

    id = sql.Column(sql.Integer, primary_key=True, nullable=False)
    revoke_id = sql.Column(sql.Integer, sql.ForeignKey("order.id"), nullable=False)
    revoke_order = orm.relationship("Order", back_populates="revocation_confirms")
    party_k = sql.Column(sql_Key(), nullable=False)
    date = sql.Column(sql.DateTime(), nullable=False)

class Store():
    def __init__(self, uri, logger):
        self.logger = logger

        self.engine = sqlalchemy.create_engine(uri)

        from sqlalchemy.orm import scoped_session, sessionmaker
        self.Session = scoped_session(sessionmaker(bind=self.engine))

        # XXX
        self.create_schema()

    def session(self):
        return self.Session()

    def create_schema(self):
        Base.metadata.create_all(self.engine)

    def dump(self):
        meta = sql.MetaData()
        meta.reflect(bind=self.engine)  # http://docs.sqlalchemy.org/en/rel_0_9/core/reflection.html
        result = {}
        for table in meta.sorted_tables:
            result[table.name] = [dict(row) for row in self.engine.execute(table.select())]
        return result

    # keys
    def store_sk(self, sk):
        k = sk.public()

        k_sql = Key(
            k=k,
            sk=sk,
        )

        sess = self.session()
        sess.add(k_sql)
        sess.commit()

    def get_sk(self, k):
        try:
            k_sql = self.session().\
                    query(Key.sk).\
                    filter_by(k=k).\
                    one()
        except orm.exc.NoResultFound:
            return None
        else:
            return k_sql.sk

    # orders

    def store_order(self, o, sess=None):
        autocommit = sess == None
        sess = sess or self.session()

        h = order.root_hash(o)

        # check if order already exists
        # XXX might have an easier way to do this
        if sess.query(Order).filter(Order.h==h).first():
            return

        self.logger.debug(f"store order {order.format(o)}")

        o_sql = Order(
            h=h,
            type=o['type'],
            raw=order.to_raw(o),
            user_k=order.user(o),
        )

        if order.signed(o):
            o_sql.root_signer = order.root_signer(o)
            o_sql.sign_date = datetime.datetime.utcfromtimestamp(o['_sig']['dat'])
            o_sql.expiration = order.expiration(o)


            if 'exp' in o['_sig']:
                o_sql.expiration = o_sql.sign_date + datetime.timedelta(seconds=o['_sig']['exp'])

        if o['type'] == order.ALIAS_BIND:
            o_sql.bind = Bind(
                order=o_sql,
                authz_k=key.from_dict(o['authz']),
                authz_domain=o['authz']['domain'],
                rsrc_k=key.from_dict(o['rsrc']),
                rsrc_domain=o['rsrc']['domain'],
            )

        if o['type'] == order.ALIAS_REVOKE:
            o_sql.revocation = Revocation(
                order=o_sql,
                h=o['h'],
            )

            self.do_revoke(sess, o)

        sess.add(o_sql)

        for op in order.parents(o):
            self.store_order(op, sess)

        if autocommit:
            sess.commit()
            assert self.get_order(self.session(), o_sql.h) == o # DEBUG

    def do_revoke(self, sess, revoke_o):
        assert revoke_o['type'] == order.ALIAS_REVOKE

        # XXX iterate over all valid orders from the signer, parse all signatures and revoke it if contains the revoked
        # signature.

        # iterate
        def iter_revoked():
            orders = self.query_order(sess, Order)

            for o_sql in orders:
                o = order_from_sql(o_sql)
                for signed_o in order.iter_signatures(o):
                    if order.root_hash(signed_o) == revoke_o['h']:
                        yield o_sql

        for revoked_o_sql in iter_revoked():
            # revoke order from when it was signed
            revoked_o_sql.revocation_date = datetime.datetime.utcfromtimestamp(revoke_o['_sig']['dat'])
            sess.add(revoked_o_sql)

            revoked_o = order_from_sql(revoked_o_sql)
            self.logger.debug(f"revoke {revoked_o['type']} {tob64(order.root_hash(revoked_o))}")

    # low-level query

    def query_order(self, sess, *kargs):
        now = datetime.datetime.utcnow()
        return sess.query(*kargs).\
            filter(
                Order.sign_date<=now,
                (Order.expiration == None) | (now<=Order.expiration),
                (Order.revocation_date == None) | (now<=Order.revocation_date),
            )

    def get_last_order(self, sess, type_, k):
        try:
            o = self.query_order(sess, Order.raw, Order.h).\
                filter(
                    Order.type==type_,
                    Order.root_signer==k,
                ).\
                order_by(Order.sign_date.desc()).\
                one()

        except orm.exc.NoResultFound:
            return None

        else:
            return order_from_sql(o)

    def query_order_bind(self, sess, *kargs):
        return self.query_order(sess, *kargs).\
            filter(
                Order.type==order.ALIAS_BIND,
                Bind.id==Order.id,
            )

        #now = datetime.datetime.utcnow()
        #return sess.\
        #    query(*kargs).\
        #    filter(
        #        Bind.id==Order.id,
        #        Order.sign_date<=now,
        #        (Order.expiration == None) | (now<Order.expiration),
        #        (Order.revocation_date == None) | (now<=Order.revocation_date),
        #    )

    # low-level logic

    def get_order(self, sess, h):
        try:
            o_sql = self.query_order(sess, Order.raw, Order.h).\
                filter(Order.h==h).\
                one()

        except orm.exc.NoResultFound:
            return None

        else:
            return order_from_sql(o_sql)

    def get_all_order(self, sess, h):
        try:
            o_sql = sess.\
                query(Order.raw, Order.expiration, Order.revocation_date).\
                filter(Order.h==h).\
                one()

        except orm.exc.NoResultFound:
            return None

        else:
            m = dict(
                expiration=o_sql.expiration,
                revocation_date=o_sql.revocation_date,
            )
            return order_from_sql(o_sql), m

    def iter_all_orders(self, root_signer, sess=None):
        sess = sess or self.session()
        it = sess.query(Order.raw, Order.expiration).\
            filter(Order.root_signer==root_signer).\
            order_by(Order.sign_date.desc())

        for i in it:
            yield order_from_sql(i), i.expiration

    def is_bound(self, user_k, authz_k, rsrc_k):
        try:
            bind = self.query_order_bind(self.session(), Bind.id).\
                filter(
                    Order.root_signer==user_k,
                    Bind.authz_k==authz_k,
                    Bind.rsrc_k==rsrc_k,
                ).\
                one()
        except orm.exc.NoResultFound:
            return False

        else:
            return True

    def get_last_valid_subkey_order(self, k):
        o = self.get_last_order(self.session(), order.ALIAS_SUBKEY, k)
        if not o:
            return None
        order.check(o, store=self)
        return o

    def get_last_register(self, client_k):
        return self.get_last_order(self.session(), order.ALIAS_REGISTER, client_k)

    def is_party_bound(self, party_k):
        try:
            r = self.query_order_bind(self.session(), Bind.authz_k, Bind.rsrc_k, Order.root_signer).\
                filter(sql.or_(
                    Order.root_signer==party_k,
                    Bind.authz_k==party_k,
                    Bind.rsrc_k==party_k,
                )).\
                one()
        except orm.exc.NoResultFound:
            return None

        else:
            if r.authz_k == party_k:
                return "authz"
            elif r.rsrc_k == party_k:
                return "rsrc"
            else:
                assert r.root_signer == party_k
                return "user"

    def revocation(self, h):
        now = datetime.datetime.utcnow()
        try:
            o_sql = self.session().query(Order.id).\
                filter(
                    Revocation.id==Order.id,
                    Order.sign_date<=now,
                    (Order.expiration == None) | (now<Order.expiration),
                ).\
                filter(
                    Order.type==order.ALIAS_REVOKE,
                    Revocation.h==h,
                ).\
                one()

        except orm.exc.NoResultFound:
            return False

        else:
            return True

    def bulk_is_revoked(self, roothashes):
        try:
            self.session().query(Order.id).\
                filter(
                    Revocation.id==Order.id,
                    Order.type==order.ALIAS_REVOKE,
                    sql.or_(*(Revocation.h==i for i in roothashes))
                ).\
                one()

        except orm.exc.NoResultFound:
            return False

        else:
            return True

    def iter_user_resources(self, user_k, authz_k):
        it = self.query_order_bind(self.session(), Order.raw, Order.h).\
            filter(
                Order.root_signer==user_k,
                Bind.authz_k==authz_k,
            )

        return map(order_from_sql, it)

    def iter_user_grants(self, user_k):
        it = self.query_order(self.session(), Order.raw, Order.h).\
            filter(
                Order.type==order.ALIAS_AUTHZ,
                Order.root_signer==user_k,
            )
        it = list(it)
        return map(order_from_sql, it)

    def confirm_revoked(self, oh, k):
        sess = self.session()
        o = sess.query(Order.id).filter(Order.h==oh).first()

        if not o:
            raise UnknownOrderException(o)

        now = datetime.datetime.utcnow()
        rc_sql = RevocationConfirm(
            revoke_id=o.id,
            party_k=k,
            date=now,
        )
        sess.add(rc_sql)
        sess.commit()

    def pending_revocations(self, self_k, user_k=None, oh=None):
        now = datetime.datetime.utcnow()

        sess = self.session()

        # XXX optimize

        # get all revoked orders which would be still valid if revocation would
        # be unknown
        q = sess.query(Order.id, Order.type, Order.h, Order.user_k).\
            filter(
                Order.revocation_date != None,
                Order.revocation_date <= now,
                Revocation.h == Order.h,
                (Order.expiration == None) | (now <= Order.expiration),
                Order.user_k != None,
            )

        if user_k is not None:
            q = q.filter(Order.user_k == user_k)

        if oh is not None:
            q = q.filter(Order.h == oh)

        o_ids = {}
        bind_ids = set()
        user_ks = set()
        for o_sql in q:
            o_ids[o_sql.id] = o_sql.h

            if o_sql.type == order.ALIAS_BIND:
                bind_ids.add(o_sql.id)

            user_ks.add(o_sql.user_k)

        #print(o_ids, bind_ids, user_ks, flush=True)
        # get all authz & rsrcs servers from the users of the revoked orders
        q = sess.query(Bind).\
            filter(
                Bind.id==Order.id,
                Order.type==order.ALIAS_BIND,
                Order.sign_date<=now,
                (Order.expiration == None) | (now<=Order.expiration),
                sql.or_(
                    (Order.revocation_date == None) | (now<=Order.revocation_date),
                    *(Order.id == o_id for o_id in bind_ids)
                ),
                sql.or_(*(
                    Order.root_signer==user_k for user_k in user_ks
                ))
            )

        servers = {}
        for bind_sql in q:
            if bind_sql.authz_k != self_k and bind_sql.authz_k not in servers:
                servers[bind_sql.authz_k] = bind_sql.authz_domain

            if bind_sql.rsrc_k != self_k and bind_sql.rsrc_k not in servers:
                servers[bind_sql.rsrc_k] = bind_sql.rsrc_domain

        # List of confirmation
        q = sess.query(RevocationConfirm).\
            filter(
                sql.or_(*(
                    RevocationConfirm.revoke_id == o_id for o_id in o_ids
                ))
            )

        r = {h: dict(servers=dict(servers)) for h in o_ids.values()}

        for rc in q:
            oh = o_ids[rc.revoke_id]
            r[oh].pop(rc.party_k)

            if not r[oh]:
                r.pop(oh)

        if r:
            # get revocation tokens
            q = sess.query(Order.raw, Revocation.h).\
                filter(
                    Order.type==order.ALIAS_REVOKE,
                    Revocation.id==Order.id,
                    sql.or_(*(
                        Revocation.h==oh for oh in r.keys()
                    ))
                )

            for o_raw, rc_h in q:
                o = order.from_raw(o_raw)
                r[rc_h]['code'] = order.to_token(o)

        return r

def log_debug():
    import logging
    logging.basicConfig()
    logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)

if __name__ == '__main__':
    s = Store('sqlite:///:memory:')
    s.create_schema()

    k, sk = sign.ed25519_secretkey.keypair()
    k = k.to_dict()
    s.store_sk(sk)
    sk = s.get_sk(k)

    o = order.order("alias/test", foo="bar")
    sign.sign(o, sk=sk, exp=3600)
    s.store_order(o)

    print(s.get_order(order.root_hash(o)))
