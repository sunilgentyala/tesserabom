# Standards and regulatory references: verification status

This add-on emits lookup tags and standard document formats. It does not certify compliance with anything.
Each reference below records how well it was verified when this project was written (November 2026).
Re-check anything marked **Unconfirmed** against the primary source before relying on it.

## Output formats

| Reference | Use here | Status |
|---|---|---|
| CycloneDX 1.6 JSON schema | CBOM and AI-BOM documents | **Confirmed.** Output is validated against the official `bom-1.6.schema.json` in CI. |
| CycloneDX `cryptoProperties` (assetType algorithm, certificate, protocol, related-crypto-material) | CBOM structure | **Confirmed** by schema validation. |
| CycloneDX `machine-learning-model` component and `services` | AI-BOM structure | **Confirmed** by schema validation. Model cards are not yet populated. |
| DSSE envelope (PAE encoding) | Signed attestations | Implemented from the DSSE specification and covered by round-trip and tamper tests. Not cross-checked against a second implementation. |
| CycloneDX 1.7 / ECMA-424 | Possible future target | **Unconfirmed.** Field-level changes were not reviewed. |
| SPDX 3.0 AI profile, CISA "SBOM for AI" minimum elements | Possible future export | **Unconfirmed.** Publication date and field list were not retrieved. |

## Regulatory tags in `wazuh/rules/tesserabom_rules.xml`

| Tag | Source | Status |
|---|---|---|
| `dora_art8_4` | Regulation (EU) 2022/2554, Art. 8(4): identify ICT assets | Confirmed from EUR-Lex text. |
| `dora_rts_2024_1774_art6` | Delegated Regulation (EU) 2024/1774, Art. 6: encryption and cryptographic controls | Confirmed from EUR-Lex text. Paragraph numbering was not fully resolved, so tags stop at article level. |
| `dora_rts_2024_1774_art7` | Same RTS, Art. 7: cryptographic key management and certificate register | Confirmed from EUR-Lex text, article level. |
| `nydfs_500.13` | 23 NYCRR 500.13(a): asset inventory | Confirmed from the regulation text. |
| `nydfs_500.15` | 23 NYCRR 500.15: encryption of nonpublic information | Confirmed from the regulation text. |
| `pci_dss_12.3.3` | PCI DSS v4.0.1 req. 12.3.3: cryptographic cipher suites and protocols documented and reviewed at least once every 12 months, with an inventory including purpose and where used | **Corroborated, primary not reached.** The PCI SSC document returned HTTP 403. A mirror labelled v4.0.1 and several vendor sources agree on the 12-month review and the "purpose and where used" inventory. One independent write-up (v4.0 era) paraphrases the requirement differently, so quote the PCI SSC text, not this table, in any audit evidence. |
| PCI DSS 4.2.1.1 (key and certificate inventory) | Context for the certificate inventory | **Corroborated** by one secondary source. Not used as a rule tag. |
| `pqc_readiness`, `crypto_agility`, `ai_bom`, `mcp`, `drift` | Project-defined | Not regulatory. |

## Context that affects planning (not encoded in the tool)

| Item | Status |
|---|---|
| A June 2026 US executive order sets post-quantum migration deadlines (key establishment 2030, signatures 2031) and tasks CISA and NIST with CBOM minimum elements within 270 days | **Unconfirmed.** Sources disagree on the order number, and the primary text was not read. |
| NIST IR 8547 timeline (quantum-vulnerable public-key algorithms deprecated after 2030, disallowed after 2035) | **Unconfirmed** as final. The finalization date came from secondary sources only. |
| Interagency model risk guidance reported to supersede SR 11-7 (April 2026) | **Unconfirmed.** Law-firm and consultancy sources only. |
| OpenSSH 9.0: `sntrup761x25519-sha512@openssh.com` is the default key exchange for ssh(1) and sshd(8) | **Confirmed** from the official 9.0 release notes. Note that sntrup is not a NIST standard. |
| OpenSSH 9.9: `mlkem768x25519-sha256` added and "available by default" for ssh(1) and sshd(8) | **Confirmed** from the official 9.9 release notes. |
| OpenSSH 10.0: `mlkem768x25519-sha256` "now used by default for key agreement" | **Confirmed** from the official 10.0 release notes, which name ssh(1), the client, only. |
| OpenSSL 3.5 adds ML-KEM, ML-DSA and SLH-DSA (FIPS 203, 204, 205), is an LTS release, and prefers a hybrid X25519MLKEM768 TLS group by default | **Corroborated** by several secondary sources and the project's pre-release announcement. The final release post was not fetched directly. The tool only relies on the 3.5 threshold for ML-KEM. |
| Wazuh 4.14.x has no native CBOM, crypto inventory or AI inventory | A targeted search of the 4.14.x release notes and changelogs (4.14.0 through 4.14.10) found no SBOM, CBOM, cryptographic inventory, AI inventory or post-quantum feature. The 4.14.0 inventory expansion covers browser extensions, services, users and groups. No public roadmap page was found, so future plans are unknown. Not every release's full notes were read, and the 5.0 line was still a release candidate. |

## Wazuh behaviour

| Item | Status |
|---|---|
| Decoders and rules produce the expected alerts | **Confirmed** on Wazuh 4.14.10 with `wazuh-logtest` (`scripts/logtest_docker.sh`). |
| `pci_dss_*` group tags are promoted to the native `rule.pci_dss` field | **Confirmed** in the same run. |
| Command wodle delivers the raw JSON line, decoded by the built-in `json` decoder (location `command_tesserabom`) | **Confirmed** on a live 4.14.10 manager running the wodle locally. The `ossec: output: 'tag':` prefix applies to `<localfile>` command collection only. |
| A remote agent reporting to a separate manager | **Not tested.** |
| Wazuh 5.x (Engine replaces analysisd) | **Not tested.** Rule and decoder syntax may need changes. |

## Detection claims and their limits

- **TLS post-quantum status** is what the endpoint negotiates with this client. If the client library cannot
  report the negotiated group, the status is recorded as unknown and no finding is raised.
- **SSH post-quantum status** is inferred from `sshd_config` and the `ssh -V` version. It is not read from a
  running daemon, so an effective config that differs from the file can be missed. The version comes from the
  `ssh` client binary as a stand-in for `sshd`; they normally ship in the same OpenSSH package, but a host
  running mismatched versions would be misjudged. "Available by default" is not the same as "negotiated":
  a connection only uses a post-quantum hybrid if the client offers one too.
- **`hndl_exposure`** is the share of determinable key-exchange surfaces without a post-quantum hybrid. It is a
  prioritisation heuristic, not a validated risk model.
