import json
import base64

# import pysodium as sodium


class Boxer:
    def __init__(self, sk=None):
        # XXX
        pass

    def encrypt(self, o):
        o_json = json.dumps(o)
        code = base64.b64encode(o_json.encode('utf-8')).decode('ascii')
        return code

    def decrypt(self, code):
        o_json = base64.b64decode(code.encode('ascii')).decode('utf-8')
        o = json.loads(o_json)
        return o
