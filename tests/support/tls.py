import datetime as dt
import ipaddress
import ssl
import threading
import time
from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def create_ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TLS test CA")])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .sign(key, hashes.SHA256())
    )
    return certificate, key


def issue_certificate(
    ca: tuple[x509.Certificate, ec.EllipticCurvePrivateKey],
    serial: int,
    *,
    client: bool = False,
    validity: str = "valid",
) -> tuple[bytes, bytes]:
    issuer, issuer_key = ca
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    before = now - dt.timedelta(hours=1)
    after = now + dt.timedelta(days=1)
    if validity == "expired":
        before, after = now - dt.timedelta(days=2), now - dt.timedelta(days=1)
    elif validity == "future":
        before, after = now + dt.timedelta(days=1), now + dt.timedelta(days=2)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            False,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH
                    if client
                    else ExtendedKeyUsageOID.SERVER_AUTH
                ]
            ),
            False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def client_context(ca: x509.Certificate) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(
        cadata=ca.public_bytes(serialization.Encoding.PEM).decode()
    )
    return context


def wait_until(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        remaining = deadline - time.monotonic()
        assert remaining > 0, "TLS state did not converge before the deadline"
        threading.Event().wait(min(0.02, remaining))


def peer_serial(connection: ssl.SSLSocket | ssl.SSLObject) -> int:
    return x509.load_der_x509_certificate(
        connection.getpeercert(binary_form=True)
    ).serial_number
