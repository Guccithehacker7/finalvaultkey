import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


def _ensure_directory(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _cert_not_valid_after(cert) -> datetime:
    """Return timezone-aware not_valid_after; supports cryptography <42 and >=42."""
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _cert_not_valid_before(cert) -> datetime:
    """Return timezone-aware not_valid_before; supports cryptography <42 and >=42."""
    try:
        return cert.not_valid_before_utc
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=timezone.utc)


def initialize_root_ca(ca_key_path: str, ca_cert_path: str):
    ca_key_file = Path(ca_key_path)
    ca_cert_file = Path(ca_cert_path)
    _ensure_directory(ca_key_file)
    _ensure_directory(ca_cert_file)

    if ca_key_file.exists() and ca_cert_file.exists():
        with ca_key_file.open("rb") as key_fd:
            private_key = serialization.load_pem_private_key(
                key_fd.read(), password=None, backend=default_backend()
            )
        with ca_cert_file.open("rb") as cert_fd:
            certificate = x509.load_pem_x509_certificate(cert_fd.read(), backend=default_backend())
        return private_key, certificate

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VaultKey Enterprise Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "VaultKey Root CA"),
        ]
    )

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    with ca_key_file.open("wb") as key_fd:
        key_fd.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with ca_cert_file.open("wb") as cert_fd:
        cert_fd.write(certificate.public_bytes(serialization.Encoding.PEM))

    return private_key, certificate


def generate_user_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def issue_user_certificate(user, public_key, ca_private_key, ca_certificate):
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, user.username),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, user.email),
        ]
    )

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )

    certificate = cert_builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    return certificate


def validate_certificate(certificate_pem: bytes, root_ca_certificate):
    certificate = x509.load_pem_x509_certificate(certificate_pem, backend=default_backend())
    root_public_key = root_ca_certificate.public_key()

    try:
        root_public_key.verify(
            signature=certificate.signature,
            data=certificate.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=certificate.signature_hash_algorithm,
        )
    except Exception as exc:
        raise ValueError("Certificate signature validation failed") from exc

    now = datetime.now(timezone.utc)

    if _cert_not_valid_before(certificate) > now:
        raise ValueError("Certificate is not yet valid")

    if _cert_not_valid_after(certificate) < now:
        raise ValueError("Certificate has expired")

    return certificate


def load_user_private_key(path: str, passphrase: bytes):
    with open(path, "rb") as key_fd:
        return serialization.load_pem_private_key(key_fd.read(), password=passphrase, backend=default_backend())
