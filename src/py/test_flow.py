from nose.tools import *

from pprint import pprint
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

    ### Initialize all parties
    rsrc = logic.Resource('rsrc.alias', DB_URI, secretkey.default().generate())
    authz = logic.Authorization('authz.alias', DB_URI, secretkey.default().generate())
    client = logic.Client(DB_URI, secretkey.default().generate(), redirect_uri="http://client.alias/alias/cb")
    user = logic.User(authz, DB_URI, secretkey.default().generate())

    ### Bind user's authz and ressource server
    if not user.store.is_bound(user.k, authz.k, rsrc.k):
        bind_token = user.bind(authz.k_dict, rsrc.k_dict)

        rsrc.bound(bind_token)
        authz.bound(bind_token)
        print("bind_token", len(bind_token))

        #print("="*80)
        assert user.store.is_bound(user.k, authz.k, rsrc.k)
        #print("="*80)

    ### Client asks user for authorization and user grants
    request_args = client.request_args(["google.photos.*"])
    grant_code = user.authorize(request_args)
    print("grant_code", len(grant_code))
    #pprint(order.deserialize(grant_code))

    ### Client generate TLS certificate
    client_crt, client_crt_sk = certificate.generate(datetime.timedelta(seconds=3600))
    client_crt_finger = certificate.fingerprint(client_crt, 'sha256')
    client_crt_token = client.tls_certificate(client_crt)

    ### Client asks for access token
    token_args = client.token_args(grant_code, cert_token=client_crt_token)
    token_resp = authz.token(**token_args)
    access_token = token_resp['access_token']
    print("access_token", len(access_token))
    #pprint(order.deserialize(access_token))

    ### Client check access token

    user_k, scopes = rsrc.parse_access_token(access_token, client_crt_finger)
    print(f"user:{user_k} scopes:{scopes}")


    ### User revoke grant
    grant_o = user.from_token(grant_code)
    revoke_token = user.revoke(grant_o, None)
    authz.revoked(revoke_token)
    rsrc.revoked(revoke_token)
    print("revoke token", len(revoke_token))


    ### Check access token again
    with assert_raises(order.RevokedOrderException) as cm:
        print(rsrc.parse_access_token(access_token, client_crt_finger))

