# Changelog

## 0.2.0

Renamed the project to **tesserabom**. This is a breaking change.

- Python package, CLI command and PyPI-style name: `tesserabom`
- Log JSON namespace and Wazuh field names: `tesserabom.*` (was `cryptoai.*`)
- Command wodle tag: `tesserabom`; rule and decoder files: `tesserabom_rules.xml`, `tesserabom_decoders.xml`
- Signing key passphrase variable: `TESSERABOM_KEY_PASSPHRASE`
- Rule IDs 100900 to 100999 are unchanged

## 0.1.1

- Fix: decoders and rules did not fire on a real Wazuh manager. Wrapped command-wodle lines are now parsed by a child
  of the built-in `ossec` decoder, and bare JSON lines rely on the built-in `json` decoder. Found by testing on
  Wazuh 4.14.10.
- Add `scripts/logtest_docker.sh` to repeat that test.
- Tolerate certificates with malformed extensions in trust stores.

## 0.1.0

Initial alpha.

- Certificate, TLS, SSH and crypto-library discovery with CycloneDX 1.6 CBOM output
- Local model, MCP server and AI runtime discovery with CycloneDX 1.6 AI-BOM output
- Baseline, drift and cryptographic downgrade detection
- DSSE Ed25519 attestations with `keygen` and `verify`
- Wazuh decoders, rules, agent snippet and logtest samples
- CI with schema validation, bandit and pip-audit
