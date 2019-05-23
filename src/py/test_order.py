from nose.tools import assert_raises

import test_datetime; test_datetime.patch()    # noqa E702
import datetime

from copy import deepcopy

from key import secretkey, key
import order


def dummy_order(**kwargs):
    return order.new("test", foo={"bar": [42, b"\xde\xad\xbe\xef"]}, **kwargs)


def test():
    for name in secretkey.algos():
        sk_cls = secretkey.from_algo(name)
        yield do_new, sk_cls
        yield do_subkey, sk_cls


def do_new(sk_cls):
    o = dummy_order()
    assert not order.signed(o)
    assert order.root_signer(o) is None
    assert order.expiration(o) is None
    assert not list(order.parents(o))
    o_unsigned = deepcopy(o)

    with test_datetime.past():
        raw = order.to_raw(o)
        code = order.to_token(o)
        assert o == order.from_token(code)
        assert o == order.from_raw(raw)

    raw = order.to_raw(o)
    code = order.to_token(o)
    assert o == order.from_token(code)
    assert o == order.from_raw(raw)

    with test_datetime.future():
        raw = order.to_raw(o)
        code = order.to_token(o)
        assert o == order.from_token(code)
        assert o == order.from_raw(raw)

    sk = sk_cls.generate()
    order.sign(o, sk)
    assert order.signed(o)
    assert order.root_signer(o) == sk.public()
    assert o != o_unsigned
    assert order.expiration(o) is None
    assert not list(order.parents(o))
    assert list(order.iter_signed(o)) == [o]

    with test_datetime.past():
        raw = order.to_raw(o)
        code = order.to_token(o)
        with assert_raises(order.FutureSignatureException):
            order.from_token(code)

        assert o == order.from_raw(raw)

    raw = order.to_raw(o)
    code = order.to_token(o)
    assert order.from_raw(raw) == o
    assert order.from_token(code) == o

    with test_datetime.future():
        raw = order.to_raw(o)
        code = order.to_token(o)
        assert o == order.from_token(code)
        assert o == order.from_raw(raw)


def do_subkey(sk_cls):
    sk = sk_cls.generate()
    k = sk.public()

    sub_sk = sk_cls.generate()
    assert sub_sk != sk
    sub_k = sub_sk.public()
    assert sub_k != k

    # generate subkey
    sub_o = order.new(order.ALIAS_SUBKEY, exp=3600, **sub_k.to_dict())
    order.sign(sub_o, sk=sk)

    # subkey is invalid in the past
    with test_datetime.past():
        raw = order.to_raw(sub_o)
        code = order.to_token(sub_o)
        with assert_raises(order.FutureSignatureException):
            order.from_token(code)

        assert sub_o == order.from_raw(raw)

    # subkey is valid just before its expiration
    with test_datetime.debug(datetime.datetime.utcfromtimestamp(sub_o['_sig']['dat'] + sub_o['exp'] - .1)):
        raw = order.to_raw(sub_o)
        code = order.to_token(sub_o)
        assert order.from_raw(raw) == sub_o
        assert order.from_token(code) == sub_o

    # subkey is invalid after its expiration
    with test_datetime.debug(datetime.datetime.utcfromtimestamp(sub_o['_sig']['dat'] + sub_o['exp'])):
        raw = order.to_raw(sub_o)
        code = order.to_token(sub_o)
        with assert_raises(order.ExpiredOrderException):
            order.from_token(code)
        assert sub_o == order.from_raw(raw)

    # signed order with subkey before it was signed is invalid
    with test_datetime.debug(datetime.datetime.utcfromtimestamp(sub_o['_sig']['dat'] - .1)):
        o = dummy_order()
        with assert_raises(order.FutureSignatureException):
            order.sign(o, sk=sub_sk, k=sub_o)

        # assert order.signed(o)
        # assert order.root_signer(o) == k
        # assert key.from_dict(o['_sig']['k']) == sub_k

        # raw = order.to_raw(o)
        # code = order.to_token(o)
        # with assert_raises(order.FutureSignatureException):
        #     order.from_token(code)
        # assert o == order.from_raw(raw)

    # signed order with expired subkey is invalid
    with test_datetime.debug(datetime.datetime.utcfromtimestamp(sub_o['_sig']['dat'] + sub_o['exp'])):
        o = dummy_order()
        with assert_raises(order.ExpiredOrderException):
            order.sign(o, sk=sub_sk, k=sub_o)

        # assert order.signed(o)
        # assert order.root_signer(o) == k
        # assert key.from_dict(o['_sig']['k']) == sub_k

        # raw = order.to_raw(o)
        # code = order.to_token(o)
        # with assert_raises(order.ExpiredOrderException):
        #     order.from_token(code)
        # assert o == order.from_raw(raw)

    # signed order with valid subkey is valid
    with test_datetime.debug(datetime.datetime.utcfromtimestamp(sub_o['_sig']['dat'] + sub_o['exp'] - .1)):
        o = dummy_order()
        order.sign(o, sk=sub_sk, k=sub_o)

        assert order.signed(o)
        assert order.root_signer(o) == k
        assert key.from_dict(o['_sig']['k']) == sub_k

        raw = order.to_raw(o)
        code = order.to_token(o)
        assert o == order.from_token(code)
        assert o == order.from_raw(raw)

    # signed order with valid subkey in the future is valid
    with test_datetime.future():
        raw = order.to_raw(o)
        code = order.to_token(o)
        assert o == order.from_token(code)
        assert o == order.from_raw(raw)

    # signed expirating order with valid subkey is valid
    with test_datetime.debug(datetime.datetime.utcfromtimestamp(sub_o['_sig']['dat'] + sub_o['exp'] - .1)):
        o = dummy_order(exp=3600)
        order.sign(o, sk=sub_sk, k=sub_o)

        assert 'exp' in o
        assert order.signed(o)
        assert order.root_signer(o) == k
        assert key.from_dict(o['_sig']['k']) == sub_k

        raw = order.to_raw(o)
        code = order.to_token(o)
        assert o == order.from_token(code)
        assert o == order.from_raw(raw)

    # signed expirating order in the future is invalid
    with test_datetime.debug(datetime.datetime.utcfromtimestamp(o['_sig']['dat'] + o['exp'])):
        raw = order.to_raw(o)
        code = order.to_token(o)
        with assert_raises(order.ExpiredOrderException):
            order.from_token(code)
        assert o == order.from_raw(raw)

    # signed with expirating signature order with valid subkey is valid
    with test_datetime.debug(datetime.datetime.utcfromtimestamp(sub_o['_sig']['dat'] + sub_o['exp'] - .1)):
        o = dummy_order()
        order.sign(o, sk=sub_sk, k=sub_o, exp=3600)

        assert 'exp' not in o
        assert order.signed(o)
        assert 'exp' in o['_sig']
        assert order.root_signer(o) == k
        assert key.from_dict(o['_sig']['k']) == sub_k

        raw = order.to_raw(o)
        code = order.to_token(o)
        assert o == order.from_token(code)
        assert o == order.from_raw(raw)

    # signed with expirating signature order with valid subkey is valid
    with test_datetime.debug(datetime.datetime.utcfromtimestamp(o['_sig']['dat'] + o['_sig']['exp'])):
        raw = order.to_raw(o)
        code = order.to_token(o)
        with assert_raises(order.ExpiredSignatureException):
            order.from_token(code)
        assert o == order.from_raw(raw)
