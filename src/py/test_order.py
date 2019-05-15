from nose.tools import *

import os
from copy import deepcopy

from key import secretkey, key
import order

def dummy_order():
    return order.new("test", foo={"bar": [42, b"\xde\xad\xbe\xef"]})

def test():
    for name in secretkey.algos():
        sk_cls = secretkey.from_algo(name)
        yield do_new, sk_cls
        yield do_subkey, sk_cls

def do_new(sk_cls):
    o = dummy_order()
    assert not order.signed(o)
    assert order.root_signer(o) == None
    assert order.expiration(o) == None
    assert not list(order.parents(o))
    o_unsigned = deepcopy(o)

    sk = sk_cls.generate()
    order.sign(o, sk)
    assert order.signed(o)
    assert order.root_signer(o) == sk.public()
    assert o != o_unsigned
    assert order.expiration(o) == None
    assert not list(order.parents(o))

    raw = order.to_raw(o)
    code = order.to_token(o)
    assert order.from_raw(raw) == o
    assert order.from_token(code) == o

def do_subkey(sk_cls):
    sk = sk_cls.generate()
    k = sk.public()

    sub_sk = sk_cls.generate()
    assert sub_sk != sk
    sub_k = sub_sk.public()
    assert sub_k != k


    sub_o = order.new(order.ALIAS_SUBKEY, **sub_k.to_dict())
    order.sign(sub_o, sk=sk)

    o = dummy_order()
    order.sign(o, sk=sub_sk, k=sub_o)

    assert order.signed(o)
    assert order.root_signer(o) == k
    assert key.from_dict(o['_sig']['k']) == sub_k
