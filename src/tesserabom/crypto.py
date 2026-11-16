"""Cryptographic asset discovery: certificates, TLS endpoints, SSH, crypto libraries."""

import datetime as dt
import hashlib
import warnings
import os
import re
import socket
import ssl
import subprocess  # nosec B404
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from .util import MAX_CERT_FILE_BYTES, read_bounded, walk_files

# Legacy trust-store roots include certificates with non-positive serials; parsing them is intended.
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

CERT_SUFFIXES = (".pem", ".crt", ".cer", ".der")
MAX_CERTS_PER_FILE = 600
MAX_CERTS_TOTAL = 5000
EXPIRY_WARN_DAYS = 30

# Public-key families broken by Shor's algorithm on a cryptographically relevant quantum computer.
QUANTUM_VULNERABLE = {"rsa", "ec", "dsa", "dh", "ed25519", "ed448", "x25519", "x448"}
WEAK_SIG_HASHES = {"md5", "sha1"}
TLS_RANK = {"SSLv3": 0, "TLSv1": 1, "TLSv1.1": 2, "TLSv1.2": 3, "TLSv1.3": 4}

# NIST SP 800-57 Part 1 comparable strengths for integer-factoring keys.
_RSA_STRENGTH = [(15360, 256), (7680, 192), (3072, 128), (2048, 112), (1024, 80)]
_EC_STRENGTH = {"secp256r1": 128, "secp384r1": 192, "secp521r1": 256, "secp256k1": 128}


def _rsa_classical_level(bits: int) -> int:
    for threshold, level in _RSA_STRENGTH:
        if bits >= threshold:
            return level
    return 0


def _utc(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _cert_times(cert: x509.Certificate) -> Tuple[dt.datetime, dt.datetime]:
    nb = getattr(cert, "not_valid_before_utc", None) or _utc(cert.not_valid_before)
    na = getattr(cert, "not_valid_after_utc", None) or _utc(cert.not_valid_after)
    return nb, na


def describe_public_key(key: Any) -> Dict[str, Any]:
    if isinstance(key, rsa.RSAPublicKey):
        return {"family": "rsa", "name": "RSA-%d" % key.key_size, "bits": key.key_size,
                "classical_level": _rsa_classical_level(key.key_size)}
    if isinstance(key, ec.EllipticCurvePublicKey):
        curve = key.curve.name
        return {"family": "ec", "name": "ECDSA-%s" % curve, "bits": key.curve.key_size,
                "curve": curve, "classical_level": _EC_STRENGTH.get(curve, key.curve.key_size // 2)}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"family": "ed25519", "name": "Ed25519", "bits": 256, "classical_level": 128}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"family": "ed448", "name": "Ed448", "bits": 456, "classical_level": 224}
    if isinstance(key, dsa.DSAPublicKey):
        return {"family": "dsa", "name": "DSA-%d" % key.key_size, "bits": key.key_size,
                "classical_level": _rsa_classical_level(key.key_size)}
    return {"family": "unknown", "name": type(key).__name__, "bits": 0, "classical_level": 0}


def certificate_asset(cert: x509.Certificate, source: str, store: str) -> Dict[str, Any]:
    nb, na = _cert_times(cert)
    fp = cert.fingerprint(hashes.SHA256()).hex()
    try:
        pub = describe_public_key(cert.public_key())
    except (ValueError, TypeError):
        pub = {"family": "unknown", "name": "unparseable", "bits": 0, "classical_level": 0}
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        sig_hash = None
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except (x509.ExtensionNotFound, ValueError):
        # Absent, or malformed in the wild (real trust stores contain such certificates).
        is_ca = False
    return {
        "kind": "certificate",
        "id": "cert:" + fp[:32],
        "fingerprint_sha256": fp,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string,
        "signature_oid": cert.signature_algorithm_oid.dotted_string,
        "signature_hash": sig_hash,
        "public_key": pub,
        "is_ca": bool(is_ca),
        "self_signed": cert.subject == cert.issuer,
        "quantum_vulnerable": pub["family"] in QUANTUM_VULNERABLE,
        "source": source,
        "store": store,
    }


def _safe_asset(cert: x509.Certificate, source: str, store: str) -> Optional[Dict[str, Any]]:
    """Build an asset, skipping certificates the parser cannot fully read."""
    try:
        return certificate_asset(cert, source, store)
    except (ValueError, TypeError):
        return None


def certificate_findings(asset: Dict[str, Any], now: Optional[dt.datetime] = None) -> List[Dict[str, Any]]:
    now = now or dt.datetime.now(dt.timezone.utc)
    out: List[Dict[str, Any]] = []
    not_after = dt.datetime.fromisoformat(asset["not_after"])
    label = asset["subject"][:120]
    # A self-signed root is a trust anchor: its own signature and validity window are not
    # used for path validation, so only leaf and intermediate certificates are judged on them.
    judged = not (asset["self_signed"] or asset["is_ca"])
    if judged:
        if not_after < now:
            out.append(_finding("cert_expired", "high", asset["id"], "%s expired %s" % (label, asset["not_after"])))
        elif (not_after - now).days <= EXPIRY_WARN_DAYS:
            out.append(_finding("cert_expiring", "medium", asset["id"],
                                "%s expires %s" % (label, asset["not_after"])))
    if asset["signature_hash"] in WEAK_SIG_HASHES and not asset["self_signed"]:
        out.append(_finding("cert_weak_signature", "high", asset["id"],
                            "%s signed with %s" % (label, asset["signature_hash"])))
    pk = asset["public_key"]
    if pk["family"] == "rsa" and pk["bits"] < 2048:
        out.append(_finding("cert_weak_key", "medium" if asset["self_signed"] else "high", asset["id"],
                            "%s uses %s" % (label, pk["name"])))
    return out


def _finding(kind: str, severity: str, asset_id: str, detail: str, **extra: Any) -> Dict[str, Any]:
    data = {"finding": kind, "severity": severity, "asset": asset_id, "detail": detail}
    data.update(extra)
    return data


def _load_cert_bytes(data: bytes) -> List[x509.Certificate]:
    certs: List[x509.Certificate] = []
    if b"-----BEGIN CERTIFICATE-----" in data:
        try:
            certs = list(x509.load_pem_x509_certificates(data))
        except ValueError:
            certs = []
    else:
        try:
            certs = [x509.load_der_x509_certificate(data)]
        except ValueError:
            certs = []
    return certs[:MAX_CERTS_PER_FILE]


def default_cert_dirs() -> List[str]:
    if os.name == "nt":
        return []
    candidates = ["/etc/ssl/certs", "/etc/pki/tls/certs", "/etc/pki/ca-trust/source/anchors",
                  "/usr/local/share/ca-certificates", "/etc/letsencrypt/live"]
    return [p for p in candidates if os.path.isdir(p)]


def scan_cert_dirs(dirs: Iterable[str]) -> List[Dict[str, Any]]:
    assets: Dict[str, Dict[str, Any]] = {}
    for root in dirs:
        for path in walk_files(root):
            if len(assets) >= MAX_CERTS_TOTAL:
                return list(assets.values())
            if not path.lower().endswith(CERT_SUFFIXES):
                continue
            data = read_bounded(path, MAX_CERT_FILE_BYTES)
            if not data:
                continue
            for cert in _load_cert_bytes(data):
                asset = _safe_asset(cert, "file:" + path, "filesystem")
                if asset:
                    assets.setdefault(asset["id"], asset)
    return list(assets.values())


def scan_windows_store() -> List[Dict[str, Any]]:
    if os.name != "nt":
        return []
    assets: Dict[str, Dict[str, Any]] = {}
    for store_name in ("MY", "ROOT"):
        try:
            entries = ssl.enum_certificates(store_name)  # type: ignore[attr-defined]
        except (OSError, AttributeError):
            continue
        for der, encoding, _trust in entries:
            if encoding != "x509_asn" or len(assets) >= MAX_CERTS_TOTAL:
                continue
            for cert in _load_cert_bytes(der):
                asset = _safe_asset(cert, "windows-store:" + store_name, store_name.lower())
                if asset:
                    assets.setdefault(asset["id"], asset)
    return list(assets.values())


# ---------------------------------------------------------------------------
# TLS probing (loopback only)
# ---------------------------------------------------------------------------

def probe_tls(port: int, host: str = "127.0.0.1", timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """Handshake with a local listener and record what it negotiates.

    Verification is disabled on purpose: the goal is to observe the negotiated
    parameters of whatever the endpoint presents, including invalid certificates.
    No application data is sent, and only loopback addresses are permitted.
    """
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("TLS probing is restricted to loopback addresses")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=None) as tls:
                version = tls.version()
                cipher = tls.cipher()
                der = tls.getpeercert(binary_form=True)
                group_fn = getattr(tls, "group", None)
                group = group_fn() if callable(group_fn) else None
    except (OSError, ssl.SSLError):
        return None
    pq: Optional[bool] = None
    if group:
        pq = "mlkem" in group.lower() or "kyber" in group.lower()
    endpoint = {
        "kind": "tls-endpoint",
        "id": "tls:%s:%d" % (host, port),
        "host": host,
        "port": port,
        "version": version,
        "cipher": cipher[0] if cipher else None,
        "key_exchange_group": group,
        "pq_hybrid_negotiated": pq,
        "certificate_id": None,
    }
    cert_asset = None
    if der:
        for cert in _load_cert_bytes(der):
            cert_asset = _safe_asset(cert, "tls:%s:%d" % (host, port), "network")
            if cert_asset:
                endpoint["certificate_id"] = cert_asset["id"]
    return {"endpoint": endpoint, "certificate": cert_asset}


def tls_findings(endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    version = endpoint.get("version")
    if version in TLS_RANK and TLS_RANK[version] < TLS_RANK["TLSv1.2"]:
        out.append(_finding("tls_legacy_version", "high", endpoint["id"],
                            "%s negotiated %s" % (endpoint["id"], version)))
    if endpoint.get("pq_hybrid_negotiated") is False:
        out.append(_finding("tls_no_pq_hybrid", "info", endpoint["id"],
                            "%s negotiated a classical key exchange (%s)" % (
                                endpoint["id"], endpoint.get("key_exchange_group"))))
    return out


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

_SSH_VERSION = re.compile(r"OpenSSH_(\d+)\.(\d+)")
_PQ_KEX = ("mlkem", "sntrup", "kyber")


def default_sshd_paths() -> List[str]:
    if os.name == "nt":
        return [r"C:\ProgramData\ssh\sshd_config"]
    return ["/etc/ssh/sshd_config"]


_TRUSTED_SSH = ("/usr/bin/ssh", "/usr/local/bin/ssh", "/bin/ssh", "/opt/homebrew/bin/ssh",
                r"C:\Windows\System32\OpenSSH\ssh.exe")


_TRUSTED_SSHD = ("/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd", "/opt/homebrew/sbin/sshd")


def _trusted_binary(candidates: Iterable[str]) -> Optional[str]:
    """Return a known absolute path; never resolve through PATH (the agent often runs as root).

    On POSIX the binary must be owned by root and not writable by group or others.
    """
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        if os.name != "nt":
            info = os.stat(candidate)
            if info.st_uid != 0 or info.st_mode & 0o022:
                continue
        return candidate
    return None


def _trusted_ssh() -> Optional[str]:
    return _trusted_binary(_TRUSTED_SSH)


def _is_root() -> bool:
    return os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0


def effective_sshd_config() -> Optional[Dict[str, Any]]:
    """Ask the installed sshd for its effective configuration with `sshd -T`.

    This reflects Include files, Match defaults and compiled-in defaults, which a plain read of
    sshd_config cannot. It needs root (host keys must be readable), so it returns None otherwise.
    """
    if not _is_root():
        return None
    exe = _trusted_binary(_TRUSTED_SSHD)
    if not exe:
        return None
    try:
        proc = subprocess.run([exe, "-T"], capture_output=True, text=True,  # nosec B603
                              timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    parsed = parse_sshd_config(proc.stdout)
    return parsed if parsed["kex"] else None


def openssh_version() -> Optional[Tuple[int, int]]:
    exe = _trusted_ssh()
    if not exe:
        return None
    try:
        proc = subprocess.run([exe, "-V"], capture_output=True, text=True,  # nosec B603
                              timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    match = _SSH_VERSION.search(proc.stderr + proc.stdout)
    return (int(match.group(1)), int(match.group(2))) if match else None


def parse_sshd_config(text: str) -> Dict[str, Any]:
    kex: Optional[str] = None
    host_keys: List[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts[0].lower(), parts[1].strip()
        if key == "kexalgorithms" and kex is None:
            kex = value
        elif key == "hostkey":
            host_keys.append(value)
    return {"kex": kex, "host_keys": host_keys}


def ssh_pq_status(kex: Optional[str], version: Optional[Tuple[int, int]]) -> Optional[bool]:
    """True/False when determinable, None when the effective KEX list is unknown."""
    if kex:
        if kex[0] in "+-^":
            # Modifier on the compiled-in default; only decidable with a known default.
            if version is None:
                return None
            default_pq = version >= (9, 0)
            if kex[0] == "-":
                return False if any(p in kex.lower() for p in _PQ_KEX) else default_pq
            return default_pq or any(p in kex.lower() for p in _PQ_KEX)
        return any(p in kex.lower() for p in _PQ_KEX)
    if version is None:
        return None
    # OpenSSH 9.0 made sntrup761x25519 default; 10.0 made mlkem768x25519 default.
    return version >= (9, 0)


def scan_ssh(config_paths: Iterable[str]) -> Dict[str, Any]:
    version = openssh_version()
    kex: Optional[str] = None
    host_keys: List[str] = []
    config_found = None
    source = None
    effective = effective_sshd_config()
    if effective:
        kex, host_keys, config_found, source = effective["kex"], effective["host_keys"], "sshd -T", "sshd -T"
    else:
        for path in config_paths:
            raw = read_bounded(path, 500_000)
            if raw is None:
                continue
            parsed = parse_sshd_config(raw.decode("utf-8", "replace"))
            config_found, source = path, "sshd_config file"
            kex = parsed["kex"]
            host_keys = parsed["host_keys"]
            break
    if config_found is None and version is None:
        return {"assets": [], "findings": []}
    pq = ssh_pq_status(kex, version)
    endpoint = {
        "kind": "ssh-server",
        "id": "ssh:sshd",
        "version": "%d.%d" % version if version else None,
        "kex_config": kex,
        "pq_kex": pq,
        "config": config_found,
        "config_source": source or "version only",
        "host_key_files": host_keys,
    }
    findings = []
    if pq is False:
        findings.append(_finding("ssh_no_pq_kex", "info", endpoint["id"],
                                 "SSH key exchange has no post-quantum hybrid (OpenSSH %s)" % endpoint["version"]))
    return {"assets": [endpoint], "findings": findings}


# ---------------------------------------------------------------------------
# Crypto libraries
# ---------------------------------------------------------------------------

_OPENSSL_VER = re.compile(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)")


def openssl_asset() -> Dict[str, Any]:
    text = ssl.OPENSSL_VERSION
    match = _OPENSSL_VER.search(text)
    pqc_capable: Optional[bool] = None
    if match:
        pqc_capable = (int(match.group(1)), int(match.group(2))) >= (3, 5)
    return {
        "kind": "library",
        "id": "lib:openssl-python-runtime",
        "name": "OpenSSL",
        "version": ".".join(match.groups()) if match else text,
        "raw_version": text,
        "ml_kem_capable": pqc_capable,
        "source": "python-ssl-module:" + sys.version.split()[0],
    }


def collect(cert_dirs: Optional[List[str]], tls_ports: List[int], ssh_paths: List[str]) -> Dict[str, Any]:
    certs: Dict[str, Dict[str, Any]] = {}
    for asset in scan_cert_dirs(cert_dirs if cert_dirs is not None else default_cert_dirs()):
        certs.setdefault(asset["id"], asset)
    for asset in scan_windows_store():
        certs.setdefault(asset["id"], asset)
    endpoints: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    for port in tls_ports:
        result = probe_tls(port)
        if not result:
            continue
        endpoints.append(result["endpoint"])
        findings.extend(tls_findings(result["endpoint"]))
        if result["certificate"]:
            certs.setdefault(result["certificate"]["id"], result["certificate"])
    for asset in certs.values():
        findings.extend(certificate_findings(asset))
    ssh = scan_ssh(ssh_paths)
    findings.extend(ssh["findings"])
    return {
        "certificates": list(certs.values()),
        "tls_endpoints": endpoints,
        "ssh": ssh["assets"],
        "libraries": [openssl_asset()],
        "findings": findings,
    }


def hndl_exposure(tls_endpoints: List[Dict[str, Any]], ssh: List[Dict[str, Any]]) -> Optional[float]:
    """Share of observed key-exchange surfaces known to lack a post-quantum hybrid (0.0 to 1.0).

    A transparent heuristic for prioritisation, not a validated risk model.
    Surfaces whose status could not be determined are excluded; None if none were determinable.
    """
    states = [e["pq_hybrid_negotiated"] for e in tls_endpoints if e.get("pq_hybrid_negotiated") is not None]
    states += [s["pq_kex"] for s in ssh if s.get("pq_kex") is not None]
    if not states:
        return None
    return round(sum(1 for s in states if s is False) / len(states), 3)


def asset_fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
