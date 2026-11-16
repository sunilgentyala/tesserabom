import json
import subprocess
import sys

import pytest

from tesserabom import bom, diffbom


def crypto(certs=(), pq=True):
    return {"certificates": list(certs), "ssh": [], "libraries": [],
            "tls_endpoints": [{"id": "tls:127.0.0.1:443", "version": "TLSv1.3", "cipher": "X", "host": "127.0.0.1",
                               "port": 443, "key_exchange_group": "X25519MLKEM768" if pq else "x25519",
                               "pq_hybrid_negotiated": pq, "certificate_id": None}]}


def ai_data(servers=()):
    return {"models": [], "runtimes": [], "mcp_servers": list(servers)}


def server(spec="aaa", url=None):
    return {"id": "mcp:mcp.json:s", "name": "s", "config": "/x/mcp.json", "command": "npx", "args": ["pkg"],
            "url": url, "env_keys": [], "header_keys": [], "spec_sha256": spec}


def test_identical_documents_have_no_diff():
    d = bom.build_cbom("a", crypto())
    r = diffbom.diff_documents(d, bom.build_cbom("b", crypto()))
    assert r == {"added": [], "removed": [], "changed": []}


def test_pq_regression_is_reported_as_property_change():
    r = diffbom.diff_documents(bom.build_cbom("h", crypto(pq=True)), bom.build_cbom("h", crypto(pq=False)))
    (change,) = r["changed"]
    assert change["ref"] == "component:crypto/tls:127.0.0.1:443"
    assert "property:tesserabom:pq-hybrid-negotiated" in change["fields"]


def test_mcp_spec_change_detected_in_aibom():
    old = bom.build_aibom("h", ai_data([server("aaa")]))
    new = bom.build_aibom("h", ai_data([server("bbb")]))
    r = diffbom.diff_documents(old, new)
    assert r["changed"][0]["fields"] == ["property:tesserabom:spec-sha256"]
    assert diffbom.diff_documents(old, bom.build_aibom("h", ai_data()))["removed"] == ["service:mcp:mcp.json:s"]


def test_load_rejects_non_cyclonedx(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"hello": 1}))
    with pytest.raises(ValueError):
        diffbom.load(str(p))


def test_cli_diff_exit_codes(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(bom.build_cbom("h", crypto(pq=True))))
    b.write_text(json.dumps(bom.build_cbom("h", crypto(pq=False))))
    base = [sys.executable, "-m", "tesserabom", "diff"]
    same = subprocess.run(base + [str(a), str(a)], capture_output=True, text=True)
    assert same.returncode == 0 and "0 added, 0 removed, 0 changed" in same.stdout
    diff = subprocess.run(base + [str(a), str(b), "--json"], capture_output=True, text=True)
    assert diff.returncode == 1 and json.loads(diff.stdout)["changed"]
