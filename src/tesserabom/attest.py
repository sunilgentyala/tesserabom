"""DSSE-signed attestations (Ed25519) so an inventory can be proven untampered.

Note: Ed25519 is itself a classical signature. It authenticates today's
inventories; a post-quantum signature suite is future work.
"""

import base64
import hashlib
import json
import os
import stat
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .util import atomic_write_private

PAYLOAD_TYPE = "application/vnd.cyclonedx+json"
PASSPHRASE_ENV = "TESSERABOM_KEY_PASSPHRASE"  # nosec B105


def _pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def _passphrase() -> Optional[bytes]:
    value = os.environ.get(PASSPHRASE_ENV)
    return value.encode() if value else None


def keyid_for(public_key: ed25519.Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(raw).hexdigest()[:16]


def keygen(directory: str) -> Dict[str, str]:
    os.makedirs(directory, exist_ok=True)
    priv_path = os.path.join(directory, "tesserabom-signing.key")
    pub_path = os.path.join(directory, "tesserabom-signing.pub")
    if os.path.exists(priv_path):
        raise FileExistsError("refusing to overwrite " + priv_path)
    key = ed25519.Ed25519PrivateKey.generate()
    pw = _passphrase()
    enc = serialization.BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
    atomic_write_private(priv_path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc).decode())
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    atomic_write_private(pub_path, pub.decode())
    return {"private": priv_path, "public": pub_path, "keyid": keyid_for(key.public_key()),
            "encrypted": str(bool(pw)).lower()}


def _load_private(path: str) -> ed25519.Ed25519PrivateKey:
    if os.name != "nt":
        mode = os.stat(path).st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError("signing key %s must not be accessible by group or others" % path)
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=_passphrase())
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("signing key must be Ed25519")
    return key


def sign(document: Dict[str, Any], key_path: str) -> Dict[str, Any]:
    key = _load_private(key_path)
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    sig = key.sign(_pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": keyid_for(key.public_key()), "sig": base64.b64encode(sig).decode()}],
    }


def verify(envelope: Dict[str, Any], pub_path: str) -> Dict[str, Any]:
    """Return the verified payload document or raise ValueError."""
    with open(pub_path, "rb") as fh:
        pub = serialization.load_pem_public_key(fh.read())
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        raise ValueError("verification key must be Ed25519")
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise ValueError("unexpected payloadType")
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        sigs = envelope["signatures"]
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("malformed envelope") from exc
    expected_id = keyid_for(pub)
    message = _pae(PAYLOAD_TYPE, payload)
    for entry in sigs:
        if not isinstance(entry, dict) or entry.get("keyid") != expected_id:
            continue
        try:
            pub.verify(base64.b64decode(entry["sig"], validate=True), message)
            return json.loads(payload)
        except (InvalidSignature, ValueError, KeyError):
            continue
    raise ValueError("no valid signature for key %s" % expected_id)
