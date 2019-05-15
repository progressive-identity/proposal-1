import re
import hashlib

from utils import tob64, fromb64
import config


class KeyException(Exception):
    pass


class UnknownAlgorithmException(KeyException):
    pass


class MalformedKeyException(KeyException):
    pass


class key:
    STR_RE = re.compile(r"(?P<kb64>[a-zA-Z0-9_-]+)\.(?P<algo>[a-z0-9]+)")

    @classmethod
    def algos(cls):
        return {subcls.NAME: subcls for subcls in cls.__subclasses__()}

    @classmethod
    def from_algo(cls, algo):
        try:
            return cls.algos()[algo]

        except KeyError:
            raise UnknownAlgorithmException(algo)

    @classmethod
    def from_str(cls, s):
        m = cls.STR_RE.match(s)
        if not m:
            raise MalformedKeyException(s)

        m = m.groupdict()
        algo, kb64 = m['algo'], m['kb64']

        return cls.from_algo(algo)(fromb64(kb64))

    @classmethod
    def from_dict(cls, d):
        return cls.from_algo(d['alg'])(d['raw'])

    def __init__(self, raw):
        self.raw = raw

    def __str__(self):
        return f"{tob64(self.raw)}.{self.NAME}"

    def __repr__(self):
        return "<key {}>".format(self)

    def to_dict(self):
        return dict(alg=self.NAME, raw=self.raw)

    def __eq__(self, other):
        # XXX ugly
        return str(self) == str(other)

    def __hash__(self):
        return hash((self.NAME, self.raw))


class secretkey:
    STR_RE = re.compile(r"(?P<kb64>[a-zA-Z0-9_-]+)\.(?P<algo>[a-z0-9]+)\.secret")

    @classmethod
    def default(cls):
        return cls.from_algo(config.DEFAULT_KEY_ALGO)

    @classmethod
    def algos(cls):
        return {subcls.NAME: subcls for subcls in cls.__subclasses__()}

    @classmethod
    def from_algo(cls, algo):
        try:
            return cls.algos()[algo]

        except KeyError:
            raise UnknownAlgorithmException(algo)

    @classmethod
    def from_str(cls, s):
        m = cls.STR_RE.match(s)
        if not m:
            raise MalformedKeyException(s)

        m = m.groupdict()
        algo, kb64 = m['algo'], m['kb64']

        return cls.from_algo(algo)(fromb64(kb64))

    def __str__(self):
        return f"{tob64(self.raw)}.{self.NAME}.secret"

    def __init__(self, raw):
        self.raw = raw

    def __repr__(self):
        return "<secretkey>"

    def __eq__(self, other):
        # XXX ugly
        return str(self) == str(other)

    def __hash__(self):
        return hash((self.NAME, self.raw))


# secp256k1 + sha256
try:
    import ecdsa

except ImportError:
    pass

else:
    class secp256k1_secretkey(secretkey):
        NAME = "secp256k1"

        @classmethod
        def generate(cls):
            sk = ecdsa.SigningKey.generate(
                curve=ecdsa.curves.SECP256k1,
                hashfunc=hashlib.sha256,
            ).to_string()
            return cls(sk)

        def public(self):
            k = self._h.get_verifying_key().to_string()
            return secp256k1_key(k)

        def __init__(self, raw):
            super().__init__(raw)
            self._h = ecdsa.SigningKey.from_string(
                self.raw,
                curve=ecdsa.curves.SECP256k1,
                hashfunc=hashlib.sha256,
            )

        def sign(self, h):
            return self._h.sign(h)

    class secp256k1_key(key):
        NAME = "secp256k1"

        def __init__(self, raw):
            super().__init__(raw)
            self._h = ecdsa.VerifyingKey.from_string(
                self.raw,
                curve=ecdsa.curves.SECP256k1,
                hashfunc=hashlib.sha256,
            )

        def verify(self, proof, h):
            try:
                self._h.verify(proof, h)

            except ecdsa.keys.BadSignatureError:
                return False

            else:
                return True

try:
    import pysodium as sodium

except ImportError:
    pass

else:
    class ed25519_secretkey(secretkey):
        NAME = 'ed25519'

        @classmethod
        def generate(cls):
            _, sk = sodium.crypto_sign_keypair()
            return cls(sk)

        def public(self):
            k = sodium.crypto_sign_sk_to_pk(self.raw)
            return ed25519_key(k)

        def sign(self, h):
            return sodium.crypto_sign_detached(h, self.raw)

    class ed25519_key(key):
        NAME = 'ed25519'

        def verify(self, proof, h):
            try:
                sodium.crypto_sign_verify_detached(proof, h, self.raw)

            except ValueError:
                return False

            else:
                return True


def use_sk(path):
    try:
        with open(path, "r") as fh:
            return secretkey.from_str(fh.read())

    except FileNotFoundError:
        sk = secretkey.default().generate()

        with open(path, "w") as fh:
            fh.write(str(sk))

        return sk
