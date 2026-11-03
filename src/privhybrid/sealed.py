"""Seal a result to a user's public key so a scheduled job can leave it while nobody is signed in (docs/SCHEDULED-JOBS-DESIGN.md).

X25519 (ephemeral key per item) + HKDF-SHA256 + AES-GCM. Only the private key opens it, and that key sits encrypted under the
user's password key. A MAC under a key derived from the scheduler key S stops anyone who can write the inbox but cannot read
the Keychain; it does not stop malware running as the same user (it can read S).
"""
import base64
import hashlib
import hmac
import json
import secrets
from typing import Any, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO_SEAL = b"privhybrid-inbox-v1"
RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
RAW_PRIV = dict(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption())


class SealError(ValueError):
    pass


def _b(x: bytes) -> str:
    return base64.b64encode(x).decode()


def _u(s: str) -> bytes:
    return base64.b64decode(s)


def derive(secret: bytes, info: bytes) -> bytes:
    """A purpose-specific key from the scheduler key S (separate keys for files and for the MAC)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)


def new_keypair() -> Tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    return priv.private_bytes(**RAW_PRIV), priv.public_key().public_bytes(**RAW)


def _mac(mac_key: bytes, item: dict) -> str:
    msg = json.dumps({k: item[k] for k in ("v", "id", "seq", "epk", "nonce", "ct")}, sort_keys=True).encode()
    return _b(hmac.new(mac_key, msg, hashlib.sha256).digest())


def seal(public: bytes, obj: Any, seq: int, mac_key: bytes) -> dict:
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(**RAW)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=epk, info=INFO_SEAL).derive(eph.exchange(X25519PublicKey.from_public_bytes(public)))
    item_id, nonce = secrets.token_hex(8), secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(obj).encode(), f"{item_id}:{seq}".encode())
    item = {"v": 1, "id": item_id, "seq": seq, "epk": _b(epk), "nonce": _b(nonce), "ct": _b(ct)}
    item["mac"] = _mac(mac_key, item)
    return item


def open_item(private: bytes, item: dict, mac_key: Optional[bytes]) -> Tuple[Any, bool]:
    """(content, verified). verified is False when the MAC is wrong or the Keychain key was not available to check it."""
    try:
        if item.get("v") != 1:
            raise SealError("unknown version")
        epk, nonce, ct = _u(item["epk"]), _u(item["nonce"]), _u(item["ct"])
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=epk, info=INFO_SEAL).derive(
            X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(epk)))
        obj = json.loads(AESGCM(key).decrypt(nonce, ct, f"{item['id']}:{item['seq']}".encode()))
    except (InvalidTag, KeyError, ValueError, TypeError) as exc:
        raise SealError("could not be opened") from exc
    verified = bool(mac_key) and hmac.compare_digest(_mac(mac_key, item), str(item.get("mac", "")))
    return obj, verified
