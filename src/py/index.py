import collections
import datetime
import hashlib
import lzma
import mimetypes
import os
import re

import msgpack

def hashfile(func, fh):
    h = func()
    while True:
        chunk = fh.read(64 * 1024)

        if not chunk:
            break

        h.update(chunk)

    return h.digest()


class Collection:
    def __init__(self, fname):
        self.fname = fname

    def __repr__(self):
        return f"<alias.Collection {self.fname!r}>"

class File:
    def __init__(self, path, hashname=None, _hash=None, mimetype=None):
        # XXX take advantage of mimetype in processors

        self.path = path
        self.hashname = hashname
        self._hash = _hash
        self.mimetype = mimetype

    def hashfunc(self):
        assert self.hashname in hashlib.algorithms_guaranteed
        return getattr(hashlib, self.hashname)

    def hash(self):
        if self.hashname is None:
            return None

        if self._hash is None:
            with open(self.path, "rb") as fh:
                self._hash = hashfile(self.hashfunc(), fh)

        return self._hash

    def guess_mimetype(self):
        return mimetypes.guess_type(self.path)

MSGPACK_EXT_TYPES = [
    Collection,
    File,
]

def encode(v):
    if isinstance(v, datetime.datetime) or isinstance(v, datetime.date):
        return v.isoformat()

    elif isinstance(v, Collection):
        return msgpack.ExtType(
                MSGPACK_EXT_TYPES.index(Collection),
                packb(v.fname)
        )

    elif isinstance(v, File):
        obj = {
            'path': v.path,
            'hashname': v.hashname,
            'hash': v.hash(),
            }

        return msgpack.ExtType(
                MSGPACK_EXT_TYPES.index(File),
                packb(obj)
        )

    return v

def ext_hook(code, raw):
    if code == MSGPACK_EXT_TYPES.index(Collection):
        fname = unpackb(raw)
        return Collection(fname)

    elif code == MSGPACK_EXT_TYPES.index(File):
        obj = unpackb(raw)
        return File(path=obj['path'], hashname=obj['hashname'], _hash=obj['hash'])

    return msgpack.ExtType(code, raw)

def packb(v):
    return msgpack.packb(v, default=encode, use_bin_type=True)

def unpackb(v):
    return msgpack.unpackb(v, ext_hook=ext_hook, raw=False)

def unpacker(fh):
    return msgpack.Unpacker(fh, ext_hook=ext_hook, raw=False)

def get_index_path(root_path, *kargs):
    return os.path.join(root_path, "index", *kargs)

def compress(fpath):
    os.system(f'xz -f -T 0 "{fpath}"')

class Index:
    def __init__(self, root_path, scope):
        self.scope = scope
        self.fname = f"{self.scope}"
        self.fpath = get_index_path(root_path, self.fname)
        self.fh = None
        self.entries = 0

def walk(obj, cb):
    r = cb(obj)
    if r: return r


    if isinstance(obj, dict):
        for v in obj.values():
            r = walk(v, cb)
            if r: return r

    elif isinstance(obj, (list, tuple)):
        for i in obj:
            r = walk(i, cb)
            if r: return r

def dump(root_path, it):
    indexes = {}

    os.system(f'mkdir -p "{get_index_path(root_path)}"')

    for scope, obj in it:
        # Get or create index file handler
        idx = indexes.get(scope)
        if idx is None:
            idx = indexes[scope] = Index(root_path, scope)
            idx.fh = open(idx.fpath, "w+b")

        m = packb(obj)
        idx.fh.write(m)
        idx.entries = idx.entries + 1

    # Hash index
    hash_fpath = get_index_path(root_path, 'hash')
    with open(hash_fpath, "wb") as fh:
        def walker(v):
            if not isinstance(v, File):
                return

            m = packb([
                v.hashname,
                v._hash,
                v.path
            ])

            fh.write(m)

        walk(obj, walker)

    compress(hash_fpath)

    root_obj = {}
    for idx in indexes.values():
        # Close index
        idx.fh.close()
        idx.fh = None

        # Compress
        compress(idx.fpath)

        # Add reference to index root
        root_obj[idx.scope] = Collection(idx.fname)

    with open(get_index_path(root_path, "root"), "wb") as fh:
        fh.write(packb(root_obj))

def full_load(root_path):
    with open(get_index_path(root_path, "root"), "rb") as fh:
        r = unpackb(fh.read())

    def map_collection(obj):
        if isinstance(obj, dict):
            obj2 = {}
            for k, v in obj.items():
                obj2[k] = map_collection(v)
            obj = obj2

        elif isinstance(obj, (tuple, list)):
            obj2 = []
            for i in obj:
                obj2.append(map_collection(i))
            obj = obj2

        elif isinstance(obj, Collection):
            fpath = get_index_path(root_path, obj.fname)

            if os.path.exists(fpath + ".xz"):
                fpath = fpath + ".xz"
                file_open = lzma.open
            else:
                file_open = open

            with file_open(fpath, "rb") as fh:
                obj2 = []
                for v in unpacker(fh):
                    obj2.append(v)

            obj = obj2

        return obj

    r = map_collection(r)

    return r

def parse_scope(scope):
    # XXX implemet better parsing

    m = re.match(r"^(?P<base>[a-z\.]+)(\[(?P<conds>.*)\])?\.(?P<fields>[\{\}a-z,_*]+)$", scope)

    if not m:
        raise ValueError("invalid scope")

    m = m.groupdict()
    base, conds, fields = m['base'], m['conds'], m['fields']

    if conds:
        conds2 = []
        for cond in conds.split(','):
            cond_m = re.match(r"^(?P<k>[a-z0-9_]+)(?P<op>(<=|>=|!=|<|>|=))(?P<v>[^,]+)$", cond)

            if not cond_m:
                raise ValueError("malformed scope")

            cond_m = cond_m.groupdict()
            k, op, v = cond_m['k'], cond_m['op'], cond_m['v']

            op = {
                '<=': lambda a, b: a <= b,
                '>=': lambda a, b: a >= b,
                '<': lambda a, b: a < b,
                '>': lambda a, b: a > b,
                '=': lambda a, b: a == b,
                '!=': lambda a, b: a != b,
            }[op]

            conds2.append(lambda obj,k=k,op=op,v=v: k in obj and op(obj[k], v))

        conds = lambda obj: all(cond(obj) for cond in conds2)
    else:
        conds = lambda obj: True

    if fields != '*':
        if fields[0] == '{' and fields[-1] == '}':
            fields = fields[1:-1].split(',')
        else:
            fields = [fields]

    return base, conds, fields

def update_fields(dst, src, fields):
    if fields == '*':
        dst.update(src)
    else:
        for f in fields:
            if f in src:
                dst[f] = src[f]

def query(root_path, scopes):
    scopes = [parse_scope(scope) for scope in scopes]

    with open(get_index_path(root_path, "root"), "rb") as fh:
        r = unpackb(fh.read())

    cols = collections.defaultdict(list)
    for scope, col in r.items():
        for base, cond, fields in scopes:
            if scope == base:
                cols[col.fname].append((cond, fields))

    for fname, scopes in cols.items():
        fpath = get_index_path(root_path, fname)

        if os.path.exists(fpath + ".xz"):
            fpath = fpath + ".xz"
            file_open = lzma.open
        else:
            file_open = open

        with file_open(fpath, "rb") as fh:
            for obj in unpacker(fh):
                r = {}
                for cond, fields in scopes:
                    if cond(obj):
                        authz = True
                        update_fields(r, obj, fields)

                if r:
                    yield fname, r

def query_blob(root_path, scopes, hname, h):
    def walker(v):
        if not isinstance(v, File):
            return

        if v.hashname == hname and v._hash == h:
            return v

    for scope, obj in query(root_path, scopes):
        f = walk(obj, walker)
        if f: return f

def json_dumps(obj, **kwargs):
    import json
    import base64

    def json_default(v):
        if isinstance(v, datetime.datetime):
            return v.isoformat()

        elif isinstance(v, File):
            obj = {}

            if v._hash:
                obj.update({
                    'hashname': v.hashname,
                    'hash': v._hash,
                })

            obj['path'] = v.path

            return obj

        elif isinstance(v, bytes):
            return base64.b64encode(v).decode('utf-8')


        raise TypeError(f"invalid type: {type(v)}")

    return json.dumps(obj, default=json_default, **kwargs)

def main():
    import sys

    r = query(sys.argv[1], sys.argv[2:])

    count = 0
    for scope, v in r:
        print(scope, json_dumps(v, sort_keys=True, indent=2))
        count = count + 1

    print(f"{count} result(s)", file=sys.stderr)

if __name__ == '__main__':
    main()

