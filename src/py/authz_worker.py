import os

from celery import Celery
import requests

import config
from utils import tob64, fromb64
from key import key

app = Celery('authz_worker', broker=os.environ['ALIAS_AUTHZ_BROKER'])


@app.task
def ping():
    print('Hello, World! :-)', flush=True)


def broadcast_one_revocation(h, code, k, domain):
    url = f"https://{domain}/alias/api/revoked/"
    args = dict(code=code)
    r = requests.post(url, data=args, verify=not config.DO_NOT_VERIFY_SSL)

    if not r.ok:
        return

    r = r.json()
    if r['state'] != 'ok':
        return

    print(r, flush=True)

    url = f"http://{os.environ['ALIAS_DOMAIN']}/alias/api/confirm_revoked/"
    r = requests.post(url, data=dict(
        k=str(k),
        oh=tob64(h),
    ))

    print(r, flush=True)


@app.task
def broadcast_revocations(r):
    for i in r:
        broadcast_one_revocation(
            fromb64(i['h']),
            i['code'],
            key.from_str(i['k']),
            i['domain'],
        )
