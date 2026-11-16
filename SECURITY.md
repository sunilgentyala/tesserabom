# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's "Report a vulnerability" button on the
Security tab. Do not open a public issue for security problems. Expect an acknowledgement within a few days.

## Threat model

The collector is intended to run as a privileged Wazuh agent child process (often root or SYSTEM), so it is
written to be a poor attack target and a poor data leak.

| Concern | Control |
|---|---|
| Executing a planted binary | The only external program is `ssh -V`, called through an absolute path from a fixed list. On POSIX the binary must be owned by root and not writable by group or others. `PATH` is never consulted. No shell is used. |
| Credential leakage from AI configs | MCP `env` and `headers` values are never read into output, only the key names. URL userinfo and query strings are stripped. Tests assert that secret values never appear. |
| Network reach | TLS probing is restricted to loopback and sends no application data. Certificate verification is disabled only for that probe, because its purpose is to observe what an endpoint presents, including invalid certificates. |
| Hostile files | Reads are size-capped, symlinks are not followed, directory walks have depth and file-count caps, and model files are only hashed up to a size limit. Malformed JSON, X.509 and config files are ignored, not trusted. |
| Log injection | Findings are serialized with `json.dumps`, so untrusted strings cannot break out of a log line. |
| Output exposure | BOMs, baselines and keys are written atomically with mode 0600 where the OS supports it. |
| Signing key handling | Ed25519 keys are refused if group or world accessible (POSIX). Keys can be encrypted with a passphrase from `TESSERABOM_KEY_PASSPHRASE`. `keygen` never overwrites an existing key. |

## Known limitations

- Ed25519 attestations are classical signatures. They protect integrity today, not against a future quantum
  adversary. A post-quantum signature suite is on the roadmap.
- Output files describe real hosts (paths, hostnames, certificate subjects). Treat them as sensitive.
- The Wazuh decoders and rules were verified with `wazuh-logtest` on a Wazuh 4.14.10 manager
  (`scripts/logtest_docker.sh`), but not in an end-to-end agent run, not on Wazuh 5.x, and not in CI.
- `--all-users` reads other users' home directories and therefore needs the privileges to do so. That is its purpose.
