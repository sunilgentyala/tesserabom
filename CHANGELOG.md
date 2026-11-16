# Changelog

## 0.3.0

- New `tesserabom diff OLD NEW` compares two BOMs (two hosts, or one host over time). Exit code 1 when they differ,
  `--json` for machines.
- SSH key-exchange status now uses the effective configuration from `sshd -T` when running as root, instead of
  reading `sshd_config` alone. Falls back to the file when not root or when `sshd -T` fails. Recorded as
  `tesserabom:config-source` in the CBOM.
- MCP servers carry a `spec-sha256` fingerprint of the configured launch command, arguments, endpoint and credential
  key names, in the AI-BOM and in the drift baseline. tesserabom never launches MCP servers, so this pins what is
  configured, not what a server later advertises.

## 0.2.0

Renamed the project to **tesserabom**. This is a breaking change.

- Python package, CLI command and PyPI-style name: `tesserabom`
- Log JSON namespace and SIEM field names: `tesserabom.*` (was `cryptoai.*`)
- Command wodle tag: `tesserabom`; rule and decoder files: `tesserabom_rules.xml`, `tesserabom_decoders.xml`
- Signing key passphrase variable: `TESSERABOM_KEY_PASSPHRASE`
- Rule IDs 100900 to 100999 are unchanged
- Docs: the command wodle delivers raw JSON (verified on a live manager); the `ossec: output:` wrapper applies to
  `<localfile>` command collection only. Rules and decoders handle both forms

## 0.1.1

- Fix: decoders and rules did not fire on a real SIEM manager. Wrapped command-wodle lines are now parsed by a child
  of the built-in `ossec` decoder, and bare JSON lines rely on the built-in `json` decoder. Found by testing on
  a 4.14.10 manager.
- Add `scripts/logtest_docker.sh` to repeat that test.
- Tolerate certificates with malformed extensions in trust stores.

## 0.1.0

Initial alpha.

- Certificate, TLS, SSH and crypto-library discovery with CycloneDX 1.6 CBOM output
- Local model, MCP server and AI runtime discovery with CycloneDX 1.6 AI-BOM output
- Baseline, drift and cryptographic downgrade detection
- DSSE Ed25519 attestations with `keygen` and `verify`
- SIEM decoders, rules, agent snippet and logtest samples
- CI with schema validation, bandit and pip-audit
