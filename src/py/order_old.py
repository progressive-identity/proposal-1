import base64
import hashlib

import msgpack
#import lzo

DEFAULT_HASH = "blake2b"

def is_signed(o):
    return '_sig' in o

def get_hasher(hasher=None):
    if hasher is None:
        hasher = DEFAULT_HASH

    if isinstance(hasher, str):
        hasher = getattr(hashlib, hasher)

    assert callable(hasher)
    return hasher

class RootHash:
    def __init__(self, digest):
        self.digest = digest

    def __repr__(self):
        return f"<RootHash {base64.encode(self.digest)}>"

def order(type_, **kwargs):
    assert 'type' not in kwargs
    kwargs['type'] = type_
    return kwargs

def roothash(o, h=None):
    h = get_hasher(h)

    if isinstance(o, RootHash):
        return o.digest

    elif isinstance(o, str):
        return h(o.encode('utf-8')).digest()

    elif isinstance(o, bytes):
        return roothash(base64.b64encode(o).decode('ascii'))

    elif isinstance(o, (int, float)):
        return roothash(str(o))

    elif isinstance(o, (list, tuple)):
        h_idx, h_val = h(), h()

        for idx, v in enumerate(o):
            h_idx.update(roothash(idx, h))
            h_val.update(roothash(v, h))

        return h(h_idx.digest() + h_val.digest()).digest()

    elif isinstance(o, dict) and is_signed(o):
        assert 'order' not in o

        o2 = dict(o)
        sig_o = dict(o2.pop('_sig'))
        sig_o['order'] = o2

        assert '_sig' not in sig_o

        return roothash(sig_o, h)

    elif isinstance(o, dict):
        h_key, h_val = h(), h()

        for k, v in sorted(o.items()):
            h_key.update(roothash(k, h))
            h_val.update(roothash(v, h))

        return h(h_key.digest() + h_val.digest()).digest()

    elif o is None:
        return bytes(h().digest_size)

    else:
        raise TypeError(f"unknown type: {type(o)}")

def serialize_bin(o):
    return msgpack.packb(o, use_bin_type=True)

def serialize(o):
    os = serialize_bin(o)
    #os = lzo.compress(os, 9)
    ojb64 = base64.urlsafe_b64encode(os).decode('ascii')
    return ojb64

def deserialize_bin(os):
    return msgpack.unpackb(os, raw=False)

def deserialize(ojb64):
    os = base64.urlsafe_b64decode(ojb64.encode('ascii'))
    #os = lzo.decompress(os)
    return deserialize_bin(os)

