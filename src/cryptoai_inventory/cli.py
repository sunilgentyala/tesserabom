"""Command line entry point.

`scan` writes CycloneDX documents to --out and prints one JSON log line per
finding to stdout, which is what the Wazuh command wodle ingests.
"""

import argparse
import json
import os
import socket
import sys
from typing import Any, Dict, List, Optional

from . import __version__, ai, attest, bom, crypto, drift
from .util import atomic_write_private

SCHEMA = "cryptoai/1"


def _log(event: str, host: str, **fields: Any) -> str:
    body: Dict[str, Any] = {"event": event, "host": host, "tool_version": __version__}
    body.update(fields)
    return json.dumps({"cryptoai": body}, separators=(",", ":"), default=str)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cryptoai-inventory", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="inventory crypto and AI assets on this endpoint")
    s.add_argument("--out", default="cryptoai-out", help="directory for cbom.json and aibom.json")
    s.add_argument("--cert-dir", action="append", help="certificate directory (repeatable; replaces defaults)")
    s.add_argument("--tls-port", action="append", type=int,
                   help="loopback TLS port to probe (repeatable, default 443 and 8443)")
    s.add_argument("--ssh-config", action="append", help="sshd_config path (repeatable)")
    s.add_argument("--model-dir", action="append", help="model directory (repeatable; replaces defaults)")
    s.add_argument("--mcp-config", action="append", help="MCP config file (repeatable; replaces defaults)")
    s.add_argument("--hash-limit-mb", type=int, default=512, help="skip hashing model files larger than this")
    s.add_argument("--baseline", help="baseline file enabling drift and downgrade detection")
    s.add_argument("--no-update-baseline", action="store_true", help="compare but do not overwrite the baseline")
    s.add_argument("--sign-key", help="Ed25519 private key; writes DSSE envelopes next to the BOMs")
    s.add_argument("--all-users", action="store_true",
                   help="inspect every user home for AI assets (use when the agent runs as root or SYSTEM)")
    s.add_argument("--skip-crypto", action="store_true")
    s.add_argument("--skip-ai", action="store_true")
    s.add_argument("--no-findings-output", action="store_true", help="do not print log lines to stdout")

    k = sub.add_parser("keygen", help="create an Ed25519 signing key pair")
    k.add_argument("--dir", required=True)

    v = sub.add_parser("verify", help="verify a DSSE envelope")
    v.add_argument("envelope")
    v.add_argument("--pub", required=True)
    return p


def _write_json(path: str, doc: Dict[str, Any]) -> None:
    atomic_write_private(path, json.dumps(doc, indent=2, sort_keys=False) + "\n")


def cmd_scan(args: argparse.Namespace) -> int:
    host = socket.gethostname()
    crypto_data: Optional[Dict[str, Any]] = None
    ai_data: Optional[Dict[str, Any]] = None
    findings: List[Dict[str, Any]] = []

    if not args.skip_crypto:
        ssh_paths = args.ssh_config or crypto.default_sshd_paths()
        crypto_data = crypto.collect(args.cert_dir, args.tls_port or [443, 8443], ssh_paths)
        findings.extend(crypto_data["findings"])
    if not args.skip_ai:
        ai_data = ai.collect(args.model_dir, args.mcp_config, args.hash_limit_mb * 1024 * 1024, args.all_users)
        findings.extend(ai_data["findings"])

    if args.baseline:
        current = drift.snapshot(crypto_data, ai_data)
        previous = drift.load_baseline(args.baseline)
        if previous is not None:
            findings.extend(drift.compare(previous, current))
        if previous is None or not args.no_update_baseline:
            drift.save_baseline(args.baseline, current)

    os.makedirs(args.out, exist_ok=True)
    written = []
    docs = []
    if crypto_data is not None:
        docs.append(("cbom", bom.build_cbom(host, crypto_data)))
    if ai_data is not None:
        docs.append(("aibom", bom.build_aibom(host, ai_data)))
    for name, doc in docs:
        path = os.path.join(args.out, name + ".json")
        _write_json(path, doc)
        written.append(path)
        if args.sign_key:
            env_path = os.path.join(args.out, name + ".dsse.json")
            _write_json(env_path, attest.sign(doc, args.sign_key))
            written.append(env_path)

    if not args.no_findings_output:
        for f in findings:
            print(_log("finding", host, **f))
        summary: Dict[str, Any] = {"findings": len(findings)}
        if crypto_data is not None:
            certs = crypto_data["certificates"]
            summary.update(certificates=len(certs),
                           quantum_vulnerable_certs=sum(1 for c in certs if c["quantum_vulnerable"]),
                           tls_endpoints=len(crypto_data["tls_endpoints"]))
            exposure = crypto.hndl_exposure(crypto_data["tls_endpoints"], crypto_data["ssh"])
            if exposure is not None:
                summary["hndl_exposure"] = exposure
        if ai_data is not None:
            summary.update(models=len(ai_data["models"]), mcp_servers=len(ai_data["mcp_servers"]),
                           ai_runtimes=len(ai_data["runtimes"]))
        print(_log("summary", host, **summary))
    print("wrote: " + ", ".join(written), file=sys.stderr)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.cmd == "scan":
            return cmd_scan(args)
        if args.cmd == "keygen":
            info = attest.keygen(args.dir)
            print(json.dumps(info, indent=2))
            return 0
        if args.cmd == "verify":
            with open(args.envelope, "r", encoding="utf-8") as fh:
                envelope = json.load(fh)
            doc = attest.verify(envelope, args.pub)
            print("OK: signature valid, %d components" % len(doc.get("components", [])))
            return 0
    except (OSError, ValueError, PermissionError, FileExistsError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    return 1
