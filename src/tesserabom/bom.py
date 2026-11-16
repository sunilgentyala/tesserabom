"""CycloneDX 1.6 document builders for the CBOM and the AI-BOM."""

import datetime as dt
import uuid
from typing import Any, Dict, List, Optional

from . import __version__

SPEC_VERSION = "1.6"
NS = "tesserabom:"


def _prop(name: str, value: Any) -> Dict[str, str]:
    if isinstance(value, bool):
        value = "true" if value else "false"
    return {"name": NS + name, "value": str(value)}


def _header(host: str, now: Optional[dt.datetime]) -> Dict[str, Any]:
    now = now or dt.datetime.now(dt.timezone.utc)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": "urn:uuid:%s" % uuid.uuid4(),
        "version": 1,
        "metadata": {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{
                "type": "application", "name": "tesserabom", "version": __version__}]},
            "component": {"type": "device", "name": host, "bom-ref": "host:" + host},
        },
    }


def _primitive(family: str) -> str:
    return "pke" if family == "rsa" else "signature"


def _algorithm_component(name: str, family: str, bits: int, curve: Optional[str],
                         classical_level: int, primitive: str, oid: Optional[str] = None) -> Dict[str, Any]:
    props: Dict[str, Any] = {
        "primitive": primitive,
        "classicalSecurityLevel": classical_level,
        "nistQuantumSecurityLevel": 0,
    }
    if curve:
        props["curve"] = curve
    elif bits:
        props["parameterSetIdentifier"] = str(bits)
    crypto: Dict[str, Any] = {"assetType": "algorithm", "algorithmProperties": props}
    if oid:
        crypto["oid"] = oid
    return {"type": "cryptographic-asset", "name": name, "bom-ref": "alg/" + name,
            "cryptoProperties": crypto}


def _tls_version(value: Optional[str]) -> str:
    return (value or "").replace("TLSv", "") or "unknown"


def build_cbom(host: str, crypto: Dict[str, Any], now: Optional[dt.datetime] = None) -> Dict[str, Any]:
    doc = _header(host, now)
    comps: Dict[str, Dict[str, Any]] = {}

    for cert in crypto["certificates"]:
        pk = cert["public_key"]
        key_alg_ref = "alg/" + pk["name"]
        sig_alg_ref = "alg/" + cert["signature_algorithm"]
        comps.setdefault(key_alg_ref, _algorithm_component(
            pk["name"], pk["family"], pk["bits"], pk.get("curve"), pk["classical_level"],
            _primitive(pk["family"])))
        comps.setdefault(sig_alg_ref, {
            "type": "cryptographic-asset", "name": cert["signature_algorithm"], "bom-ref": sig_alg_ref,
            "cryptoProperties": {
                "assetType": "algorithm", "oid": cert["signature_oid"],
                "algorithmProperties": {"primitive": "signature", "nistQuantumSecurityLevel": 0}}})
        key_ref = "key/" + cert["fingerprint_sha256"][:32]
        comps[key_ref] = {
            "type": "cryptographic-asset", "name": "public-key:" + cert["subject"][:80], "bom-ref": key_ref,
            "cryptoProperties": {"assetType": "related-crypto-material",
                                 "relatedCryptoMaterialProperties": {
                                     "type": "public-key", "algorithmRef": key_alg_ref,
                                     "size": pk["bits"]}}}
        cert_ref = "crypto/" + cert["id"]
        comps[cert_ref] = {
            "type": "cryptographic-asset", "name": cert["subject"][:120] or cert["id"], "bom-ref": cert_ref,
            "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
                "subjectName": cert["subject"], "issuerName": cert["issuer"],
                "notValidBefore": cert["not_before"], "notValidAfter": cert["not_after"],
                "signatureAlgorithmRef": sig_alg_ref, "subjectPublicKeyRef": key_ref,
                "certificateFormat": "X.509"}},
            "properties": [_prop("quantum-vulnerable", cert["quantum_vulnerable"]),
                           _prop("source", cert["source"]),
                           _prop("sha256", cert["fingerprint_sha256"]),
                           _prop("is-ca", cert["is_ca"])]}

    for ep in crypto["tls_endpoints"]:
        ref = "crypto/" + ep["id"]
        props = [_prop("host", ep["host"]), _prop("port", ep["port"])]
        if ep.get("key_exchange_group"):
            props.append(_prop("key-exchange-group", ep["key_exchange_group"]))
        if ep.get("pq_hybrid_negotiated") is not None:
            props.append(_prop("pq-hybrid-negotiated", ep["pq_hybrid_negotiated"]))
        suites = [{"name": ep["cipher"]}] if ep.get("cipher") else []
        comps[ref] = {
            "type": "cryptographic-asset", "name": ep["id"], "bom-ref": ref,
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                "type": "tls", "version": _tls_version(ep.get("version")), "cipherSuites": suites}},
            "properties": props}

    for ssh in crypto["ssh"]:
        ref = "crypto/" + ssh["id"]
        props = [_prop("openssh-version", ssh.get("version") or "unknown")]
        if ssh.get("kex_config"):
            props.append(_prop("kex-config", ssh["kex_config"]))
        if ssh.get("pq_kex") is not None:
            props.append(_prop("pq-kex", ssh["pq_kex"]))
        comps[ref] = {
            "type": "cryptographic-asset", "name": "sshd", "bom-ref": ref,
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                "type": "ssh", "version": "2.0"}},
            "properties": props}

    for lib in crypto["libraries"]:
        props = [_prop("source", lib["source"])]
        if lib.get("ml_kem_capable") is not None:
            props.append(_prop("ml-kem-capable", lib["ml_kem_capable"]))
        comps["lib/" + lib["id"]] = {
            "type": "library", "name": lib["name"], "version": lib["version"],
            "bom-ref": "lib/" + lib["id"], "properties": props}

    doc["components"] = sorted(comps.values(), key=lambda c: c["bom-ref"])
    return doc


def build_aibom(host: str, ai: Dict[str, Any], now: Optional[dt.datetime] = None) -> Dict[str, Any]:
    doc = _header(host, now)
    components: List[Dict[str, Any]] = []
    for model in ai["models"]:
        comp: Dict[str, Any] = {
            "type": "machine-learning-model", "name": model["name"], "bom-ref": model["id"],
            "properties": [_prop("format", model["format"]), _prop("path", model["path"]),
                           _prop("size-bytes", model["size_bytes"]),
                           _prop("serialization-risk", model["serialization_risk"])]}
        if model["sha256"]:
            comp["hashes"] = [{"alg": "SHA-256", "content": model["sha256"]}]
        if model["magic_ok"] is not None:
            comp["properties"].append(_prop("header-matches-extension", model["magic_ok"]))
        components.append(comp)
    for rt in ai["runtimes"]:
        components.append({
            "type": "application", "name": rt["name"], "bom-ref": rt["id"],
            "properties": [_prop("category", "local-ai-runtime"),
                           _prop("loopback-listener", rt["listening_loopback"])]})
    doc["components"] = sorted(components, key=lambda c: c["bom-ref"])
    services = []
    for srv in ai["mcp_servers"]:
        svc: Dict[str, Any] = {
            "bom-ref": srv["id"], "name": srv["name"],
            "properties": [_prop("protocol", "mcp"), _prop("config", srv["config"])]}
        if srv["url"]:
            svc["endpoints"] = [srv["url"]]
        if srv["command"]:
            svc["properties"].append(_prop("command", srv["command"]))
        if srv["args"]:
            svc["properties"].append(_prop("args", " ".join(srv["args"])))
        for key in srv["env_keys"]:
            svc["properties"].append(_prop("env-key", key))
        for key in srv["header_keys"]:
            svc["properties"].append(_prop("header-key", key))
        services.append(svc)
    doc["services"] = sorted(services, key=lambda s: s["bom-ref"])
    return doc
