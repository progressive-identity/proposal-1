from nose.tools import raises

import os

import key


def test_algo():
    assert list(key.key.algos()) == list(key.secretkey.algos())

    for name in key.secretkey.algos():
        yield from do_algo(name)


def do_algo(name):
    sk_cls = key.secretkey.from_algo(name)
    k_cls = key.key.from_algo(name)
    sk = sk_cls.generate()
    assert isinstance(sk, sk_cls)
    k = sk.public()
    assert isinstance(k, k_cls)

    assert sk_cls.generate() != sk
    assert key.secretkey.from_str(str(sk)) == sk

    assert sk_cls.generate().public() != k
    assert key.key.from_str(str(k)) == k
    assert key.key.from_dict(k.to_dict()) == k

    for _ in range(4):
        yield do_sign_verify, sk, k


def do_sign_verify(sk, k):
    buf = os.urandom(1024)
    proof = sk.sign(buf)
    assert k.verify(proof, buf)

    buf2 = os.urandom(1024)
    assert buf != buf2

    assert not k.verify(proof, buf2)


@raises(key.UnknownAlgorithmException)
def test_unknown_algo_sk():
    key.secretkey.from_algo("foo")


@raises(key.UnknownAlgorithmException)
def test_unknown_algo_k():
    key.key.from_algo("foo")


@raises(key.MalformedKeyException)
def test_malformed_sk():
    key.secretkey.from_str("foo")


@raises(key.MalformedKeyException)
def test_malformed_k():
    key.key.from_str("foo")
