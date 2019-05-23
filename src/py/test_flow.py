import test_datetime; test_datetime.patch()    # noqa E702

from nose.tools import assert_raises

import datetime

import certificate
import logic
import order
import store
from key import secretkey

import os


def test_flow():
    if os.environ.get("SQL_DEBUG"):
        store.log_debug()

    import logging
    logging.basicConfig()
    logging.getLogger('alias').setLevel(logging.DEBUG)

    DB_URI = "sqlite:///:memory:"

    AUTHZ_DOMAIN = "authz.alias"
    NAME = "foo@" + AUTHZ_DOMAIN
    SCOPES = ["google.photo.*"]

    # Initialize all parties
    rsrc = logic.Resource('rsrc.alias', DB_URI, secretkey.default().generate())
    authz = logic.Authorization('authz.alias', DB_URI, secretkey.default().generate())
    client = logic.Client(DB_URI, secretkey.default().generate(), redirect_uri="http://client.alias/alias/cb")
    user = logic.User(authz, DB_URI, secretkey.default().generate())

    # assert user is not bound to anything
    assert not user.store.is_bound(user.k, authz.k, rsrc.k)
    assert not user.get_rsrc_servers()

    # Bind user's authz and ressource server
    bind_token = user.bind(authz.k_dict, rsrc.k_dict)

    rsrc.bound(bind_token)
    authz.bound(bind_token)
    print("bind_token", len(bind_token))

    # assert user is bound
    assert user.store.is_bound(user.k, authz.k, rsrc.k)
    rsrc_servers = user.get_rsrc_servers()
    assert list(rsrc_servers) == [str(rsrc.k)]
    assert rsrc_servers[str(rsrc.k)]['domain'] == rsrc.domain

    # assert no clients is defined
    assert not user.clients()[0]

    # Client asks user for authorization and user grants
    _, request_args = client.authorize(NAME, SCOPES)
    grant_code = user.authorize(request_args)
    grant_o = user.from_token(grant_code)
    grant_oh = order.root_hash(grant_o)
    print("grant_code", len(grant_code))

    # assert client is defined
    assert user.clients()[0] == {
        str(client.k): {sc: {grant_oh: grant_o} for sc in SCOPES}
    }

    # assert client's grant expires
    with test_datetime.future():
        assert user.clients()[0] == {
            str(client.k): {sc: {grant_oh: grant_o} for sc in SCOPES}
        }

    # Client generate TLS certificate
    client_crt, client_crt_sk = certificate.generate(datetime.timedelta(seconds=3600))
    client_crt_finger = certificate.fingerprint(client_crt, 'sha256')
    client_crt_token = client.tls_certificate(client_crt)

    with test_datetime.future():
        with assert_raises(order.ExpiredSignatureException):
            order.from_token(client_crt_token)

    # Client asks for access token
    _, token_args = client.token_req(AUTHZ_DOMAIN, grant_code, crt_token=client_crt_token)
    token_resp = authz.token(**token_args)
    access_token = token_resp['access_token']
    print("access_token", len(access_token))

    with test_datetime.future():
        with assert_raises(order.ExpiredSignatureException):
            order.from_token(access_token)

    # assert client is defined
    assert user.clients()[0] == {
        str(client.k): {sc: {grant_oh: grant_o} for sc in SCOPES}
    }

    # assert client is defined in the future (a refresh token had been generated)
    with test_datetime.future():
        assert user.clients()[0] == {
            str(client.k): {sc: {grant_oh: grant_o} for sc in SCOPES}
        }

    # Client check access token
    user_k, scopes = rsrc.parse_access_token(access_token, client_crt_finger)
    print(f"user:{user_k} scopes:{scopes}")

    # Renew access token
    with test_datetime.delta(days=1):
        with assert_raises(order.ExpiredSignatureException):
            rsrc.parse_access_token(access_token, client_crt_finger)

        with assert_raises(order.ExpiredSignatureException):
            order.from_token(client_crt_token)

        # Client generate TLS certificate
        client_crt, client_crt_sk = certificate.generate(datetime.timedelta(seconds=3600))
        client_crt_finger = certificate.fingerprint(client_crt, 'sha256')
        new_client_crt_token = client.tls_certificate(client_crt)
        assert new_client_crt_token != client_crt_token
        client.from_token(new_client_crt_token)

        # Client asks for access token
        _, token_args = client.token_req(AUTHZ_DOMAIN, grant_code, crt_token=new_client_crt_token)
        token_resp = authz.token(**token_args)
        new_access_token = token_resp['access_token']
        assert new_access_token != access_token
        print("new_access_token", len(new_access_token))

        assert rsrc.parse_access_token(new_access_token, client_crt_finger) == (user_k, scopes)

    assert not authz.pending_revocations()

    # User revoke grant
    revoke_token = user.revoke(grant_o, None)
    authz.revoked(revoke_token)

    pr = authz.pending_revocations()
    assert grant_oh in pr
    assert pr[grant_oh]['code'] == revoke_token
    assert pr[grant_oh]['servers'][rsrc.k] == rsrc.domain

    rsrc.revoked(revoke_token)
    print("revoke token", len(revoke_token))

    # Check access token again
    with assert_raises(order.RevokedOrderException):
        print(rsrc.parse_access_token(access_token, client_crt_finger))

    # try to refresh tokens
    _, token_args = client.token_req(AUTHZ_DOMAIN, grant_code, crt_token=client_crt_token)

    with assert_raises(order.RevokedOrderException):
        authz.token(**token_args)
