import json
import os
import sys

import pytest

from tesserabom import attest, bom, drift


def tls(version="TLSv1.3", pq=True):
    return {"certificates": [], "ssh": [], "libraries": [],
            "tls_endpoints": [{"id": "tls:127.0.0.1:443", "version": version, "cipher": "X",
                               "key_exchange_group": None, "pq_hybrid_negotiated": pq,
                               "certificate_id": None, "host": "127.0.0.1", "port": 443}]}


def test_drift_added_removed_changed_and_downgrade():
    old = drift.snapshot(tls(), None)
    assert drift.compare(old, drift.snapshot(tls(), None)) == []
    kinds = {f["finding"] for f in drift.compare(old, drift.snapshot(tls("TLSv1.2", False), None))}
    assert kinds == {"crypto_downgrade", "drift_changed"}
    assert {f["finding"] for f in drift.compare(old, {})} == {"drift_removed"}
    assert {f["finding"] for f in drift.compare({}, old)} == {"drift_added"}


def test_upgrade_is_not_downgrade():
    old = drift.snapshot(tls("TLSv1.2", False), None)
    kinds = {f["finding"] for f in drift.compare(old, drift.snapshot(tls("TLSv1.3", True), None))}
    assert kinds == {"drift_changed"}


def test_drift_overflow_is_capped():
    new = {"cert:%d" % i: {"x": i} for i in range(100)}
    assert len(drift.compare({}, new)) == drift.PER_KIND_CAP + 1


def test_baseline_roundtrip_and_corrupt(tmp_path):
    p = str(tmp_path / "b.json")
    drift.save_baseline(p, {"a:1": {"k": 1}})
    assert drift.load_baseline(p) == {"a:1": {"k": 1}}
    (tmp_path / "bad.json").write_text("{}")
    assert drift.load_baseline(str(tmp_path / "bad.json")) is None


def test_attest_sign_verify_and_tamper(tmp_path):
    info = attest.keygen(str(tmp_path))
    doc = {"bomFormat": "CycloneDX", "components": [1, 2]}
    env = attest.sign(doc, info["private"])
    assert attest.verify(env, info["public"]) == doc
    env["payload"] = env["payload"][:-4] + "AAAA"
    with pytest.raises(ValueError):
        attest.verify(env, info["public"])


def test_attest_wrong_key_rejected(tmp_path):
    a = attest.keygen(str(tmp_path / "a"))
    b = attest.keygen(str(tmp_path / "b"))
    env = attest.sign({"x": 1}, a["private"])
    with pytest.raises(ValueError):
        attest.verify(env, b["public"])


def test_keygen_refuses_overwrite(tmp_path):
    attest.keygen(str(tmp_path))
    with pytest.raises(FileExistsError):
        attest.keygen(str(tmp_path))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_group_readable_key_refused(tmp_path):
    info = attest.keygen(str(tmp_path))
    os.chmod(info["private"], 0o644)
    with pytest.raises(PermissionError):
        attest.sign({"x": 1}, info["private"])


def test_bom_validates_against_official_schema(cert_dir, tmp_path):
    schema_dir = os.environ.get("CYCLONEDX_SCHEMA_DIR")
    if not schema_dir:
        pytest.skip("set CYCLONEDX_SCHEMA_DIR to the CycloneDX schema directory")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
    from validate_cyclonedx import main as validate
    from tesserabom import ai, crypto
    c = crypto.collect([str(cert_dir)], [], [])
    a = ai.collect([], [], 1000)
    cb, ab = tmp_path / "c.json", tmp_path / "a.json"
    cb.write_text(json.dumps(bom.build_cbom("h", c)))
    ab.write_text(json.dumps(bom.build_aibom("h", a)))
    assert validate(schema_dir, [str(cb), str(ab)]) == 0
