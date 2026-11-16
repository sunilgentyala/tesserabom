"""AI asset discovery: local model files, MCP server configs, local runtimes.

Privacy rule: environment variable VALUES and header values from MCP configs
are never read into output. Only key names are recorded.
"""

import os
import re
import socket
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from .util import load_json_file, sha256_file, walk_files

MODEL_SUFFIXES = {
    ".gguf": "gguf", ".safetensors": "safetensors", ".onnx": "onnx",
    ".pt": "pytorch", ".pth": "pytorch", ".ckpt": "checkpoint",
    ".pkl": "pickle", ".pickle": "pickle", ".h5": "keras-hdf5",
}
# Formats that deserialize through pickle or can embed executable objects.
SERIALIZATION_RISK = {"pytorch", "checkpoint", "pickle"}
MAX_MODELS = 2000
SECRET_KEY = re.compile(r"(key|token|secret|password|passwd|credential|auth)", re.I)
PINNED_NPX = re.compile(r"@\d+(\.\d+){0,2}([-+][\w.]+)?$")


def user_homes(all_users: bool) -> List[str]:
    """Home directories to inspect. An agent running as root sees only root's home by default."""
    homes = [os.path.expanduser("~")]
    if all_users:
        for parent in ("/home", "/Users", r"C:\Users"):
            if not os.path.isdir(parent):
                continue
            try:
                entries = sorted(os.listdir(parent))
            except OSError:
                continue
            for name in entries:
                path = os.path.join(parent, name)
                if name.lower() in ("shared", "public", "default", "default user", "all users")                         or name.startswith(".") or os.path.islink(path) or not os.path.isdir(path):
                    continue
                homes.append(path)
    seen, unique = set(), []
    for home in homes:
        key = os.path.normcase(os.path.realpath(home))
        if key not in seen:
            seen.add(key)
            unique.append(home)
    return unique


def default_model_dirs(homes: List[str]) -> List[str]:
    rel = [(".ollama", "models"), (".lmstudio", "models"), (".cache", "lm-studio", "models"),
           (".cache", "huggingface", "hub"), (".cache", "torch", "hub"), ("models",)]
    out = []
    for home in homes:
        for parts in rel:
            path = os.path.join(home, *parts)
            if os.path.isdir(path):
                out.append(path)
    return out


def model_format(path: str) -> Optional[str]:
    return MODEL_SUFFIXES.get(os.path.splitext(path)[1].lower())


def magic_matches(path: str, fmt: str) -> Optional[bool]:
    """Compare the file header with its extension; None when no check exists."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return None
    if fmt == "gguf":
        return head[:4] == b"GGUF"
    if fmt == "safetensors":
        if len(head) < 9:
            return False
        header_len = int.from_bytes(head[:8], "little")
        return 0 < header_len < 100_000_000 and head[8:9] == b"{"
    if fmt in ("pickle",):
        return head[:1] == b"\x80"
    return None


def scan_models(dirs: Iterable[str], hash_limit: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for root in dirs:
        for path in walk_files(root, max_depth=8):
            fmt = model_format(path)
            if not fmt:
                continue
            if len(out) >= MAX_MODELS:
                return out
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            digest = sha256_file(path, hash_limit)
            out.append({
                "kind": "model",
                "id": "model:" + (digest[:32] if digest else "path-" + re.sub(r"\W+", "_", path)[-48:]),
                "name": os.path.basename(path),
                "path": path,
                "format": fmt,
                "size_bytes": size,
                "sha256": digest,
                "serialization_risk": fmt in SERIALIZATION_RISK,
                "magic_ok": magic_matches(path, fmt),
            })
    return out


def model_findings(model: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    if model["serialization_risk"]:
        out.append(_f("model_unsafe_serialization", "medium", model["id"],
                      "%s uses a pickle-based format (%s)" % (model["name"], model["format"])))
    if model["magic_ok"] is False:
        out.append(_f("model_header_mismatch", "high", model["id"],
                      "%s header does not match its %s extension" % (model["name"], model["format"])))
    return out


def _f(kind: str, severity: str, asset_id: str, detail: str) -> Dict[str, Any]:
    return {"finding": kind, "severity": severity, "asset": asset_id, "detail": detail}


# ---------------------------------------------------------------------------
# MCP configuration discovery
# ---------------------------------------------------------------------------

def default_mcp_config_paths(homes: List[str]) -> List[str]:
    rel = [(".cursor", "mcp.json"), (".codeium", "windsurf", "mcp_config.json"), (".claude.json",),
           ("AppData", "Roaming", "Claude", "claude_desktop_config.json"),
           ("AppData", "Roaming", "Code", "User", "mcp.json"),
           ("Library", "Application Support", "Claude", "claude_desktop_config.json"),
           (".config", "Claude", "claude_desktop_config.json"), (".config", "Code", "User", "mcp.json")]
    paths = [os.path.join(h, *parts) for h in homes for parts in rel]
    paths += [os.path.join(os.getcwd(), ".vscode", "mcp.json"), os.path.join(os.getcwd(), ".mcp.json")]
    seen, out = set(), []
    for p in paths:
        if p not in seen and os.path.isfile(p):
            seen.add(p)
            out.append(p)
    return out


def _servers_from(doc: Any) -> Dict[str, Any]:
    if not isinstance(doc, dict):
        return {}
    for key in ("mcpServers", "servers"):
        value = doc.get(key)
        if isinstance(value, dict):
            return value
    return {}


def parse_mcp_config(path: str) -> List[Dict[str, Any]]:
    doc = load_json_file(path)
    out: List[Dict[str, Any]] = []
    servers = dict(_servers_from(doc))
    if isinstance(doc, dict) and isinstance(doc.get("projects"), dict):
        for proj in doc["projects"].values():  # Claude Code per-project servers
            for name, spec in _servers_from(proj).items():
                servers.setdefault(name, spec)
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        command = spec.get("command") if isinstance(spec.get("command"), str) else None
        args = [str(a) for a in spec.get("args", []) if isinstance(a, (str, int))] if isinstance(
            spec.get("args"), list) else []
        url = spec.get("url") if isinstance(spec.get("url"), str) else None
        env_keys = sorted(spec["env"].keys()) if isinstance(spec.get("env"), dict) else []
        header_keys = sorted(spec["headers"].keys()) if isinstance(spec.get("headers"), dict) else []
        out.append({
            "kind": "mcp-server",
            "id": "mcp:%s:%s" % (os.path.basename(path), name),
            "name": str(name),
            "config": path,
            "command": command,
            "args": args,
            "url": _strip_url_credentials(url),
            "env_keys": env_keys,
            "header_keys": header_keys,
        })
    return out


def _strip_url_credentials(url: Optional[str]) -> Optional[str]:
    if not url:
        return url
    parsed = urlparse(url)
    if parsed.username or parsed.password or parsed.query:
        host = parsed.hostname or ""
        port = ":%d" % parsed.port if parsed.port else ""
        return "%s://%s%s%s" % (parsed.scheme, host, port, parsed.path)
    return url


def _npx_package(args: List[str]) -> Optional[str]:
    for arg in args:
        if not arg.startswith("-"):
            return arg
    return None


def mcp_findings(server: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    sid, name = server["id"], server["name"]
    cmd = os.path.basename(server["command"] or "").lower()
    if cmd in ("npx", "npx.cmd", "uvx", "pipx", "bunx"):
        pkg = _npx_package(server["args"])
        if pkg and not PINNED_NPX.search(pkg) and "==" not in pkg:
            out.append(_f("mcp_unpinned_package", "medium", sid,
                          "MCP server %s runs unpinned package %s" % (name, pkg)))
    if server["url"]:
        parsed = urlparse(server["url"])
        loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if parsed.scheme == "http" and not loopback:
            out.append(_f("mcp_cleartext_remote", "high", sid,
                          "MCP server %s uses cleartext HTTP to %s" % (name, parsed.hostname)))
        elif parsed.scheme in ("http", "https") and not loopback:
            out.append(_f("mcp_remote_server", "info", sid,
                          "MCP server %s connects to remote host %s" % (name, parsed.hostname)))
    secret_keys = [k for k in server["env_keys"] + server["header_keys"] if SECRET_KEY.search(k)]
    if secret_keys:
        out.append(_f("mcp_secret_in_config", "medium", sid,
                      "MCP server %s keeps credentials in a config file (keys: %s)" % (
                          name, ", ".join(secret_keys[:5]))))
    return out


# ---------------------------------------------------------------------------
# Local runtimes
# ---------------------------------------------------------------------------

RUNTIME_PORTS = {"ollama": 11434, "lm-studio": 1234}


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_runtimes() -> Dict[str, Any]:
    runtimes, findings = [], []
    for name, port in RUNTIME_PORTS.items():
        if _port_open(port):
            runtimes.append({"kind": "ai-runtime", "id": "runtime:" + name, "name": name,
                             "port": port, "listening_loopback": True})
    ollama_host = os.environ.get("OLLAMA_HOST", "")
    if ollama_host and not re.match(r"^(https?://)?(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$", ollama_host):
        findings.append(_f("ai_runtime_exposed", "high", "runtime:ollama",
                           "OLLAMA_HOST is set to a non-loopback address"))
        if not any(r["id"] == "runtime:ollama" for r in runtimes):
            runtimes.append({"kind": "ai-runtime", "id": "runtime:ollama", "name": "ollama",
                             "port": None, "listening_loopback": False})
    return {"runtimes": runtimes, "findings": findings}


def collect(model_dirs: Optional[List[str]], mcp_paths: Optional[List[str]], hash_limit: int,
            all_users: bool = False) -> Dict[str, Any]:
    homes = user_homes(all_users)
    models = scan_models(model_dirs if model_dirs is not None else default_model_dirs(homes), hash_limit)
    servers: List[Dict[str, Any]] = []
    for path in (mcp_paths if mcp_paths is not None else default_mcp_config_paths(homes)):
        servers.extend(parse_mcp_config(path))
    rt = scan_runtimes()
    findings = list(rt["findings"])
    for m in models:
        findings.extend(model_findings(m))
    for s in servers:
        findings.extend(mcp_findings(s))
    for r in rt["runtimes"]:
        findings.append(_f("ai_runtime_present", "info", r["id"], "Local AI runtime detected: %s" % r["name"]))
    return {"models": models, "mcp_servers": servers, "runtimes": rt["runtimes"], "findings": findings}
