"""Compare two CycloneDX documents produced by tesserabom (two hosts, or one host over time)."""

import json
from typing import Any, Dict, List, Tuple

from .util import MAX_CONFIG_BYTES, read_bounded

IGNORED_PROPERTIES = {"tesserabom:source", "tesserabom:path", "tesserabom:config"}


def load(path: str) -> Dict[str, Any]:
    raw = read_bounded(path, MAX_CONFIG_BYTES * 20)
    if raw is None:
        raise ValueError("cannot read %s (missing, too large, or a symlink)" % path)
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("%s is not valid JSON" % path) from exc
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("%s is not a CycloneDX document" % path)
    return doc


def _index(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for comp in doc.get("components", []) or []:
        out["component:" + str(comp.get("bom-ref") or comp.get("name"))] = comp
    for svc in doc.get("services", []) or []:
        out["service:" + str(svc.get("bom-ref") or svc.get("name"))] = svc
    return out


def _props(item: Dict[str, Any]) -> Dict[str, str]:
    return {p["name"]: p.get("value", "") for p in item.get("properties", []) or []
            if isinstance(p, dict) and "name" in p and p["name"] not in IGNORED_PROPERTIES}


def _changed_fields(old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    fields = []
    for key in sorted(set(old) | set(new)):
        if key == "properties":
            po, pn = _props(old), _props(new)
            fields += ["property:" + n for n in sorted(set(po) | set(pn)) if po.get(n) != pn.get(n)]
        elif old.get(key) != new.get(key):
            fields.append(key)
    return fields


def diff_documents(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    a, b = _index(old), _index(new)
    changed: List[Tuple[str, List[str]]] = []
    for ref in sorted(set(a) & set(b)):
        fields = _changed_fields(a[ref], b[ref])
        if fields:
            changed.append((ref, fields))
    return {
        "added": sorted(set(b) - set(a)),
        "removed": sorted(set(a) - set(b)),
        "changed": [{"ref": r, "fields": f} for r, f in changed],
    }


def render(result: Dict[str, Any]) -> str:
    lines = ["+ " + r for r in result["added"]]
    lines += ["- " + r for r in result["removed"]]
    lines += ["~ %s (%s)" % (c["ref"], ", ".join(c["fields"])) for c in result["changed"]]
    lines.append("%d added, %d removed, %d changed" % (
        len(result["added"]), len(result["removed"]), len(result["changed"])))
    return "\n".join(lines)
