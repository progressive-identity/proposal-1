#!/usr/bin/env python3

import sys
import lzma
import re

import msgpack

def parse_args(args):
    if not args:
        return {}

    d = {}
    args = args.split(',')

    for arg in args:
        k, v = arg.split('=', 1)
        d[k] = v

    return d

def parse_scope(scope):
    RE = re.compile(r"^(?P<scope>[a-zA-Z\.]+)(\[(?P<args>[a-zA-Z0-9,=&|\(\)]+)\])?$")

    m = RE.match(scope)

    if not m:
        raise Exception("bad scope")

    m = m.groupdict()
    args = parse_args(m['args'])

    return m['scope'], args

def match_meta(meta, args):
    for k, v in args.items():
        if k not in meta or meta[k] != v:
            return False

    return True

def main():
    fpath = sys.argv[1]
    scope = sys.argv[2]

    scope = parse_scope(scope)

    with lzma.open(fpath, 'rb') as fh:
        it = msgpack.Unpacker(fh, raw=False)

        for fpath, meta in it:
            if meta['scope'] != scope[0]:
                continue

            if not match_meta(meta, scope[1]):
                continue

            print(fpath)

if __name__ == '__main__':
    main()
