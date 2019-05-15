from collections import OrderedDict
import base64
import datetime
import hashlib
import json
import lzma
import mimetypes
import os
import re
import csv
import urllib.parse

import dateutil.parser
from tqdm import tqdm


AMAZON_PATH = '/alias/amazon/'

obj = []

def progress(desc):
    def decorator(func):
        from functools import wraps
        @wraps(desc)
        def wrapper(*kargs, **kwargs):
            it = func(*kargs, **kwargs)
            it = tqdm(it, desc)
            return it
        return wrapper
    return decorator

def magic_parse(v):
    r = None

    if r is None:
        try:
            r = int(v)
        except ValueError:
            pass

    if r is None:
        try:
            r = dateutil.parser.parse(v).isoformat()
        except ValueError:
            pass

    if r is None:
        r = v

    return r

def iter_csv(fpath, k_map=None, v_map=None):
    if k_map is None: k_map = lambda x: x
    if v_map is None: v_map = lambda x: x

    with open(fpath, 'r', encoding='latin-1') as fh:
        csv_fh = csv.reader(fh)
        orig_keys = None
        new_keys = None
        for row in csv_fh:
            if orig_keys is None:
                orig_keys = row
                new_keys = [k_map(i) for i in orig_keys]
                continue

            d = OrderedDict((nk, v_map(ok, nk, v)) for ok, nk, v in zip(orig_keys, new_keys, row))

            yield d


@progress("browsing searches")
def iter_search_data():
    def k_map(k):
        m = re.match(r"^[^\(]+", k).group()
        m = m.strip().lower().replace(' ', '_')
        return m

    def v_map(ok, nk, v):
        if 'y/n' in ok.lower():
            r = bool(v)

        else:
            r = magic_parse(v)

        return r

    it = iter_csv(os.path.join(AMAZON_PATH, 'root/Search-Data.csv'), k_map, v_map)

    for i in it:
        fsqs = i['first_search_query_string']

        if fsqs:
            i['first_search_query'] = dict((k, magic_parse(v)) for k, v in urllib.parse.parse_qsl(fsqs))

        yield i

@progress("browsing order history")
def iter_order_history():
    # find order history file
    fnames = [i for i in os.listdir(os.path.join(AMAZON_PATH, 'root')) if i.lower().endswith('order history.csv')]

    assert(len(fnames) == 1)
    fname = fnames[0]
    fpath = os.path.join(AMAZON_PATH, 'root', fname)

    def map_v(ok, nk, v):
        return magic_parse(v)

    for i in iter_csv(fpath, None, map_v):
        yield i

import alias_index

def generator():
    for v in iter_search_data():
        yield "amazon.search", v

    for v in iter_order_history():
        yield "amazon.order", v

alias_index.dump(AMAZON_PATH, generator())
