"""Baseline and drift detection, including cryptographic downgrade detection."""

import hashlib
import json
from typing import Any, Dict, List, Optional

from .crypto import TLS_RANK
from .util import atomic_write_private, load_json_file

PER_KIND_CAP = 20
HIGH_SIGNAL_KINDS = {"mcp", "model", "runtime"}


def _h(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]


def snapshot(crypto: Optional[Dict[str, Any]], ai: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    state: Dict[str, Dict[str, Any]] = {}
    if crypto:
        for c in crypto["certificates"]:
            state[c["id"]] = {"key": c["public_key"]["name"], "sig": c["signature_algorithm"],
                              "not_after": c["not_after"]}
        for e in crypto["tls_endpoints"]:
            state[e["id"]] = {"version": e["version"], "cipher": e["cipher"],
                              "pq": e["pq_hybrid_negotiated"], "cert": e["certificate_id"]}
        for s in crypto["ssh"]:
            state[s["id"]] = {"pq": s["pq_kex"], "kex": s["kex_config"], "version": s["version"]}
        for lib in crypto["libraries"]:
            state[lib["id"]] = {"version": lib["version"]}
    if ai:
        for m in ai["models"]:
            state[m["id"]] = {"sha256": m["sha256"], "size": m["size_bytes"], "path": m["path"]}
        for s in ai["mcp_servers"]:
            state[s["id"]] = {"spec": s["spec_sha256"][:16]}
        for r in ai["runtimes"]:
            state[r["id"]] = {"port": r["port"]}
    return state


def load_baseline(path: str) -> Optional[Dict[str, Dict[str, Any]]]:
    doc = load_json_file(path)
    if isinstance(doc, dict) and doc.get("version") == 1 and isinstance(doc.get("assets"), dict):
        return doc["assets"]
    return None


def save_baseline(path: str, state: Dict[str, Dict[str, Any]]) -> None:
    atomic_write_private(path, json.dumps({"version": 1, "assets": state}, sort_keys=True))


def _kind(asset_id: str) -> str:
    return asset_id.split(":", 1)[0]


def _downgrade(asset_id: str, before: Dict[str, Any], after: Dict[str, Any]) -> Optional[str]:
    if _kind(asset_id) == "tls":
        rb, ra = TLS_RANK.get(before.get("version") or "", -1), TLS_RANK.get(after.get("version") or "", -1)
        if ra != -1 and rb != -1 and ra < rb:
            return "TLS version dropped from %s to %s" % (before["version"], after["version"])
    if _kind(asset_id) in ("tls", "ssh") and before.get("pq") is True and after.get("pq") is False:
        return "post-quantum hybrid key exchange no longer negotiated"
    return None


def _f(kind: str, severity: str, asset_id: str, detail: str) -> Dict[str, Any]:
    return {"finding": kind, "severity": severity, "asset": asset_id, "detail": detail}


def compare(old: Dict[str, Dict[str, Any]], new: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    buckets: Dict[str, Dict[str, List[str]]] = {}

    def note(change: str, asset_id: str) -> None:
        buckets.setdefault(change, {}).setdefault(_kind(asset_id), []).append(asset_id)

    for asset_id in sorted(set(new) - set(old)):
        note("added", asset_id)
    for asset_id in sorted(set(old) - set(new)):
        note("removed", asset_id)
    for asset_id in sorted(set(old) & set(new)):
        if old[asset_id] == new[asset_id]:
            continue
        reason = _downgrade(asset_id, old[asset_id], new[asset_id])
        if reason:
            findings.append(_f("crypto_downgrade", "high", asset_id, reason))
        note("changed", asset_id)

    for change, by_kind in buckets.items():
        for kind, ids in by_kind.items():
            severity = "medium" if (kind in HIGH_SIGNAL_KINDS and change != "removed") or change == "changed" \
                else "info"
            for asset_id in ids[:PER_KIND_CAP]:
                findings.append(_f("drift_" + change, severity, asset_id, "%s %s" % (kind, change)))
            if len(ids) > PER_KIND_CAP:
                findings.append(_f("drift_" + change, severity, kind + ":*",
                                   "%d more %s assets %s (suppressed)" % (len(ids) - PER_KIND_CAP, kind, change)))
    return findings
