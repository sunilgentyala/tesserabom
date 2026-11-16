import socket
import ssl
import threading

import pytest
from cryptography.hazmat.primitives import serialization

from conftest import make_cert, pem
from tesserabom import crypto


def test_scan_cert_dir_finds_only_certs(cert_dir):
    assets = crypto.scan_cert_dirs([str(cert_dir)])
    assert len(assets) == 3
    assert all(a["quantum_vulnerable"] for a in assets)


def test_findings_expired_and_weak_key(cert_dir):
    assets = {a["subject"]: a for a in crypto.scan_cert_dirs([str(cert_dir)])}

    def kinds(subject):
        return {f["finding"] for f in crypto.certificate_findings(assets[subject])}

    assert kinds("CN=good.example") == set()
    assert "cert_expired" in kinds("CN=old.example")
    assert "cert_weak_key" in kinds("CN=weak.example")


def test_self_signed_root_not_judged_on_expiry_or_hash():
    cert, _ = make_cert("Root", days=-5, issuer_cn="Root", ca=True)
    asset = crypto.certificate_asset(cert, "t", "t")
    assert asset["self_signed"]
    assert crypto.certificate_findings(asset) == []


def test_expiring_soon():
    cert, _ = make_cert("soon.example", issuer_cn="CA", days=10)
    asset = crypto.certificate_asset(cert, "t", "t")
    assert [f["finding"] for f in crypto.certificate_findings(asset)] == ["cert_expiring"]


def test_symlinked_cert_is_skipped(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    cert, _ = make_cert("a", issuer_cn="b")
    (tmp_path / "real.pem").write_bytes(pem(cert))
    try:
        (d / "link.pem").symlink_to(tmp_path / "real.pem")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert crypto.scan_cert_dirs([str(d)]) == []


def test_ssh_pq_status():
    assert crypto.ssh_pq_status("curve25519-sha256", (10, 0)) is False
    assert crypto.ssh_pq_status("mlkem768x25519-sha256,curve25519-sha256", (9, 0)) is True
    assert crypto.ssh_pq_status(None, (10, 0)) is True
    assert crypto.ssh_pq_status(None, (8, 4)) is False
    assert crypto.ssh_pq_status(None, None) is None
    assert crypto.ssh_pq_status("+diffie-hellman-group14-sha1", None) is None
    assert crypto.ssh_pq_status("-mlkem768x25519-sha256", (10, 0)) is False


def test_parse_sshd_config_first_kex_wins():
    parsed = crypto.parse_sshd_config("# c\nKexAlgorithms a,b\nHostKey /x\nKexAlgorithms c\n")
    assert parsed == {"kex": "a,b", "host_keys": ["/x"]}


def test_hndl_exposure():
    eps = [{"pq_hybrid_negotiated": False}, {"pq_hybrid_negotiated": True}, {"pq_hybrid_negotiated": None}]
    assert crypto.hndl_exposure(eps, []) == 0.5
    assert crypto.hndl_exposure([{"pq_hybrid_negotiated": None}], [{"pq_kex": None}]) is None


def test_probe_refuses_non_loopback():
    with pytest.raises(ValueError):
        crypto.probe_tls(443, host="192.0.2.10")


def test_probe_local_tls_server(tmp_path):
    cert, key = make_cert("localhost", issuer_cn="localhost")
    crt, keyf = tmp_path / "s.crt", tmp_path / "s.key"
    crt.write_bytes(pem(cert))
    keyf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(keyf))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
            with ctx.wrap_socket(conn, server_side=True):
                pass
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    result = crypto.probe_tls(port)
    srv.close()
    assert result and result["endpoint"]["version"] in ("TLSv1.2", "TLSv1.3")
    assert result["certificate"]["public_key"]["name"].startswith("ECDSA")
    assert result["endpoint"]["certificate_id"] == result["certificate"]["id"]


def test_ssh_binary_never_resolved_from_path(monkeypatch, tmp_path):
    fake = tmp_path / ("ssh.exe" if __import__("os").name == "nt" else "ssh")
    fake.write_text("evil")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(crypto, "_TRUSTED_SSH", ())
    assert crypto.openssh_version() is None


class _MalformedExtensions:
    """Delegates to a real certificate but fails to parse extensions, as some trust-store entries do."""

    def __init__(self, cert):
        self._cert = cert

    def __getattr__(self, name):
        return getattr(self._cert, name)

    @property
    def extensions(self):
        raise ValueError("error parsing asn1 value")


def test_malformed_extension_does_not_abort_asset_creation():
    cert, _ = make_cert("odd.example", issuer_cn="CA")
    asset = crypto.certificate_asset(_MalformedExtensions(cert), "t", "t")
    assert asset["is_ca"] is False and asset["subject"] == "CN=odd.example"


def test_unparseable_certificate_is_skipped_not_fatal(tmp_path, monkeypatch):
    d = tmp_path / "c"
    d.mkdir()
    for name in ("good", "bad"):
        cert, _ = make_cert(name, issuer_cn="CA")
        (d / (name + ".pem")).write_bytes(pem(cert))
    real = crypto.certificate_asset

    def flaky(cert, source, store):
        if "bad" in source:
            raise ValueError("boom")
        return real(cert, source, store)

    monkeypatch.setattr(crypto, "certificate_asset", flaky)
    assets = crypto.scan_cert_dirs([str(d)])
    assert [a["subject"] for a in assets] == ["CN=good"]


class _Proc:
    def __init__(self, stdout, returncode=0):
        self.stdout, self.returncode, self.stderr = stdout, returncode, ""


def test_effective_sshd_config_used_when_root(monkeypatch):
    out = "port 22\nkexalgorithms mlkem768x25519-sha256,curve25519-sha256\nhostkey /etc/ssh/ssh_host_ed25519_key\n"
    monkeypatch.setattr(crypto, "_is_root", lambda: True)
    monkeypatch.setattr(crypto, "_trusted_binary", lambda c: "/fake/sshd")
    monkeypatch.setattr(crypto.subprocess, "run", lambda *a, **k: _Proc(out))
    monkeypatch.setattr(crypto, "openssh_version", lambda: (10, 0))
    (ep,) = crypto.scan_ssh(["/nonexistent"])["assets"]
    assert ep["config_source"] == "sshd -T" and ep["pq_kex"] is True
    assert ep["host_key_files"] == ["/etc/ssh/ssh_host_ed25519_key"]


def test_effective_sshd_config_skipped_when_not_root(monkeypatch):
    monkeypatch.setattr(crypto, "_is_root", lambda: False)
    assert crypto.effective_sshd_config() is None


def test_effective_sshd_failure_falls_back_to_file(monkeypatch, tmp_path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text("KexAlgorithms curve25519-sha256\n")
    monkeypatch.setattr(crypto, "_is_root", lambda: True)
    monkeypatch.setattr(crypto, "_trusted_binary", lambda c: "/fake/sshd")
    monkeypatch.setattr(crypto.subprocess, "run", lambda *a, **k: _Proc("", returncode=255))
    monkeypatch.setattr(crypto, "openssh_version", lambda: (10, 0))
    (ep,) = crypto.scan_ssh([str(cfg)])["assets"]
    assert ep["config_source"] == "sshd_config file" and ep["pq_kex"] is False
