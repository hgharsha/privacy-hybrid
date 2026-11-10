"""Local HTTPS for the LAN link: a throwaway certificate authority signs one server certificate, then its private key is discarded,
so nothing on disk can mint other certificates. Install ca.crt on the devices that should trust this server (AirDrop it to a phone)."""
from . import fsutil
import argparse
import datetime
import ipaddress
import os
import ssl
from pathlib import Path
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DAYS = 397  # iOS and Safari reject server certificates valid longer than this


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Private Assistant"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make(folder: Path, ips: List[str], now: datetime.datetime = None) -> Path:
    """Write ca.crt, server.crt and server.key (0600) into `folder`. Returns the folder."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    folder.mkdir(parents=True, exist_ok=True)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name("Private Assistant local CA")).issuer_name(_name("Private Assistant local CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=DAYS))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    san = [x509.DNSName("localhost")] + [x509.IPAddress(ipaddress.ip_address(i)) for i in dict.fromkeys(ips)]
    leaf = (x509.CertificateBuilder().subject_name(_name("Private Assistant")).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=DAYS))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)  # Python 3.13 requires it
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))  # ca_key goes out of scope here and is never written
    (folder / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (folder / "server.crt").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    kf = folder / "server.key"
    kf.touch(mode=0o600)
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    fsutil.private(kf, 0o600)
    fsutil.private(folder, 0o700)
    return folder


def expires(folder: str) -> datetime.datetime:
    """When the server certificate in `folder` stops being valid (UTC)."""
    cert = x509.load_pem_x509_certificate((Path(folder) / "server.crt").read_bytes())
    return cert.not_valid_after_utc


def server_context(folder: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(Path(folder) / "server.crt"), str(Path(folder) / "server.key"))
    return ctx


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--ip", action="append", default=["127.0.0.1"])
    a = ap.parse_args()
    print(make(Path(a.dir), a.ip))
