from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import datetime


def generate(expires_in):
    now = datetime.datetime.utcnow()

    from cryptography.hazmat.primitives.asymmetric import ec
    # from cryptography.x509.oid import NameOID

    # generate private key
    sk = ec.generate_private_key(
        curve=ec.SECP256R1,
        backend=default_backend()
    )

    # XXX no name?
    name = x509.Name([
        # x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])

    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    crt = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(sk.public_key())
        .serial_number(1)               # XXX
        .not_valid_before(now)
        .not_valid_after(now + expires_in)
        .add_extension(basic_contraints, False)
        .sign(sk, hashes.SHA256(), default_backend())
    )

    return crt, sk


def open_certificate(path):
    with open(path, "r") as fh:
        return from_pem(fh.read())


def fingerprint(crt, algo):
    algo_cls = {
        'sha256': hashes.SHA256,
    }

    return algo, crt.fingerprint(algo_cls[algo]())


def save_certificate(path, crt, sk=None):
    crt_path = path + ".crt"
    crt_pem = to_pem(crt)

    with open(crt_path, "w") as fh:
        fh.write(crt_pem)

    if sk:
        sk_path = path + ".key"

        sk_pem = sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            encryption_algorithm=serialization.NoEncryption(),
            format=serialization.PrivateFormat.TraditionalOpenSSL,
        )

        with open(sk_path, "wb") as fh:
            fh.write(sk_pem)


def to_pem(crt):
    return crt.public_bytes(encoding=serialization.Encoding.PEM).decode('ascii')


def from_pem(pem):
    return x509.load_pem_x509_certificate(pem.encode('ascii'), default_backend())


def sk_to_pem(sk):
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('ascii')


def sk_from_pem(pem):
    return serialization.load_pem_private_key(pem.encode('ascii'), None, default_backend())
