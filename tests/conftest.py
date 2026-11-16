import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def make_cert(cn="test.example", key=None, days=365, issuer_cn=None, ca=False):
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=400))
               .not_valid_after(now + dt.timedelta(days=days)))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(key, hashes.SHA256()), key


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def cert_dir(tmp_path):
    d = tmp_path / "certs"
    d.mkdir()
    good, _ = make_cert("good.example", issuer_cn="Test CA", days=300)
    expired, _ = make_cert("old.example", issuer_cn="Test CA", days=-10)
    weak, _ = make_cert("weak.example", key=rsa.generate_private_key(public_exponent=65537, key_size=1024),
                        issuer_cn="Test CA")
    (d / "good.pem").write_bytes(pem(good))
    (d / "expired.crt").write_bytes(pem(expired))
    (d / "weak.pem").write_bytes(pem(weak))
    (d / "notes.txt").write_text("not a cert")
    return d
