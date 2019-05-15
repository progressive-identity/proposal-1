from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import datetime
import hashlib

def generate(expires_in):
    now = datetime.datetime.utcnow()

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    # generate private key
    sk = ec.generate_private_key(
        curve=ec.SECP256K1,
        backend=default_backend()
    )

    # XXX no name?
    name = x509.Name([
        #x509.NameAttribute(NameOID.COMMON_NAME, hostname)
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
    with open(path, "rb") as fh:
        pem = fh.read()

    return x509.load_pem_x509_certificate(pem, default_backend())

def fingerprint(crt, algo):
    algo_cls = {
        'sha256': hashes.SHA256,
    }

    return algo, crt.fingerprint(algo_cls[algo]())

def save_certificate(path, crt, sk=None):
    crt_path = path + ".crt"
    crt_pem = crt.public_bytes(encoding=serialization.Encoding.PEM)
    with open(crt_path, "wb") as fh:
        fh.write(crt_pem)

    if sk:
        sk_path = path + ".key"

        sk_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            encryption_algorithm=serialization.NoEncryption(),
            format=serialization.PrivateFormat.TraditionalOpenSSL,
        )

        with open(sk_path, "wb") as fh:
            fh.write(sk_pem)

if __name__ == '__main__':
    from base64 import b64encode

    crt, k = generate(datetime.timedelta(days=10*365))
    print(crt, k)
    print(b64encode(fingerprint(crt)))
