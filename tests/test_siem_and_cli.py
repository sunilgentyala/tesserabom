import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from conftest import make_cert, pem

ROOT = Path(__file__).resolve().parents[1]


def _rule_patterns():
    tree = ET.fromstring("<r>" + (ROOT / "siem/rules/tesserabom_rules.xml").read_text() + "</r>")
    ids, patterns = [], set()
    for rule in tree.iter("rule"):
        ids.append(rule.get("id"))
        for f in rule.findall("field"):
            if f.get("name") == "tesserabom.finding":
                patterns.add(f.text.strip("^$"))
    return ids, patterns


def test_rule_ids_unique_and_in_reserved_range():
    ids, _ = _rule_patterns()
    assert len(ids) == len(set(ids))
    assert all(100900 <= int(i) <= 100999 for i in ids)


def test_every_finding_kind_has_a_rule():
    src = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "src/tesserabom").glob("*.py"))
    emitted = set(re.findall(r'_(?:finding|f)\(\s*"([a-z_]+)"', src))
    emitted.discard("drift_")  # built dynamically in drift.compare
    emitted |= {"drift_added", "drift_removed", "drift_changed"}
    _, patterns = _rule_patterns()
    assert emitted - patterns == set(), "findings without a SIEM rule"
    assert patterns - emitted == set(), "rules for findings the tool never emits"


def test_decoders_wellformed():
    ET.fromstring("<r>" + (ROOT / "siem/decoders/tesserabom_decoders.xml").read_text() + "</r>")


def test_cli_end_to_end_with_drift_and_signing(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    cert, _ = make_cert("leaf.example", issuer_cn="CA", days=-3)
    (certs / "a.pem").write_bytes(pem(cert))
    models = tmp_path / "models"
    models.mkdir()
    (models / "m.gguf").write_bytes(b"GGUF" + b"\0" * 32)
    mcp = tmp_path / "mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"x": {"command": "npx", "args": ["-y", "unpinned"]}}}))
    keys, out = tmp_path / "keys", tmp_path / "out"
    base = [sys.executable, "-m", "tesserabom"]
    k = subprocess.run(base + ["keygen", "--dir", str(keys)], capture_output=True, text=True, check=True)
    assert json.loads(k.stdout)["keyid"]
    scan = base + ["scan", "--out", str(out), "--cert-dir", str(certs), "--model-dir", str(models),
                   "--mcp-config", str(mcp), "--tls-port", "1", "--ssh-config", str(tmp_path / "none"),
                   "--baseline", str(tmp_path / "base.json"),
                   "--sign-key", str(keys / "tesserabom-signing.key")]
    first = subprocess.run(scan, capture_output=True, text=True, check=True)
    lines = [json.loads(x)["tesserabom"] for x in first.stdout.splitlines()]
    kinds = {x.get("finding") for x in lines}
    assert {"cert_expired", "mcp_unpinned_package"} <= kinds
    assert not any(x.startswith("drift_") for x in kinds if x)
    assert lines[-1]["event"] == "summary"
    for name in ("cbom", "aibom"):
        v = subprocess.run(base + ["verify", str(out / (name + ".dsse.json")),
                                   "--pub", str(keys / "tesserabom-signing.pub")],
                           capture_output=True, text=True)
        assert v.returncode == 0, v.stderr
    (models / "m.gguf").write_bytes(b"GGUF" + b"\1" * 32)
    second = subprocess.run(scan, capture_output=True, text=True, check=True)
    kinds2 = {json.loads(x)["tesserabom"].get("finding") for x in second.stdout.splitlines()}
    assert "drift_added" in kinds2 and "drift_removed" in kinds2
