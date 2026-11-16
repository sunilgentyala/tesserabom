import json

from cryptoai_inventory import ai


def test_models_flagged_and_hashed(tmp_path):
    (tmp_path / "ok.gguf").write_bytes(b"GGUF" + b"\0" * 64)
    (tmp_path / "bad.gguf").write_bytes(b"MZ" + b"\0" * 64)
    (tmp_path / "w.pt").write_bytes(b"\x80\x02" + b"\0" * 8)
    (tmp_path / "readme.md").write_text("x")
    models = {m["name"]: m for m in ai.scan_models([str(tmp_path)], 10_000_000)}
    assert set(models) == {"ok.gguf", "bad.gguf", "w.pt"}
    assert models["ok.gguf"]["magic_ok"] is True and models["ok.gguf"]["sha256"]
    assert {f["finding"] for f in ai.model_findings(models["bad.gguf"])} == {"model_header_mismatch"}
    assert {f["finding"] for f in ai.model_findings(models["w.pt"])} == {"model_unsafe_serialization"}


def test_hash_limit_skips_big_files(tmp_path):
    (tmp_path / "big.gguf").write_bytes(b"GGUF" + b"\0" * 2048)
    (model,) = ai.scan_models([str(tmp_path)], 100)
    assert model["sha256"] is None and model["id"].startswith("model:path-")


def test_safetensors_header(tmp_path):
    body = b'{"a":1}'
    (tmp_path / "m.safetensors").write_bytes(len(body).to_bytes(8, "little") + body)
    (model,) = ai.scan_models([str(tmp_path)], 10_000)
    assert model["magic_ok"] is True


def _cfg(tmp_path, servers, key="mcpServers"):
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps({key: servers}))
    return str(p)


def test_mcp_never_records_secret_values(tmp_path):
    path = _cfg(tmp_path, {"s": {"command": "npx", "args": ["-y", "some-mcp"],
                                 "env": {"API_TOKEN": "sk-super-secret"}}})
    (server,) = ai.parse_mcp_config(path)
    assert "sk-super-secret" not in json.dumps(server)
    assert server["env_keys"] == ["API_TOKEN"]
    assert {f["finding"] for f in ai.mcp_findings(server)} == {"mcp_unpinned_package", "mcp_secret_in_config"}


def test_mcp_pinned_package_not_flagged(tmp_path):
    path = _cfg(tmp_path, {"s": {"command": "npx", "args": ["-y", "@scope/pkg@1.2.3"]}})
    (server,) = ai.parse_mcp_config(path)
    assert ai.mcp_findings(server) == []


def test_mcp_url_credentials_stripped_and_cleartext_flagged(tmp_path):
    path = _cfg(tmp_path, {"r": {"url": "http://user:pw@tools.example.org:8080/mcp?key=abc"}}, key="servers")
    (server,) = ai.parse_mcp_config(path)
    assert "pw" not in server["url"] and "abc" not in server["url"]
    assert {f["finding"] for f in ai.mcp_findings(server)} == {"mcp_cleartext_remote"}


def test_mcp_loopback_http_ok(tmp_path):
    path = _cfg(tmp_path, {"l": {"url": "http://localhost:3000/mcp"}})
    (server,) = ai.parse_mcp_config(path)
    assert ai.mcp_findings(server) == []


def test_malformed_config_is_ignored(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    assert ai.parse_mcp_config(str(p)) == []


def test_ollama_exposure_flag(monkeypatch):
    monkeypatch.setattr(ai, "_port_open", lambda *a, **k: False)
    monkeypatch.setenv("OLLAMA_HOST", "0.0.0.0:11434")
    assert [f["finding"] for f in ai.scan_runtimes()["findings"]] == ["ai_runtime_exposed"]
    monkeypatch.setenv("OLLAMA_HOST", "127.0.0.1:11434")
    assert ai.scan_runtimes()["findings"] == []


def test_all_users_discovers_other_homes(tmp_path, monkeypatch):
    home_a = tmp_path / "alice"
    (home_a / ".ollama" / "models").mkdir(parents=True)
    (home_a / ".ollama" / "models" / "m.gguf").write_bytes(b"GGUF" + b"\0" * 16)
    monkeypatch.setattr(ai.os.path, "expanduser", lambda p: str(tmp_path / "root"))
    assert ai.default_model_dirs([str(tmp_path / "root")]) == []
    assert ai.default_model_dirs([str(tmp_path / "root"), str(home_a)]) == [str(home_a / ".ollama" / "models")]


def test_user_homes_deduplicates(monkeypatch):
    own = ai.os.path.expanduser("~")
    assert ai.user_homes(False) == [own]
    homes = ai.user_homes(True)
    keys = [ai.os.path.normcase(ai.os.path.realpath(h)) for h in homes]
    assert len(keys) == len(set(keys))
