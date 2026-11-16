# Licensing notes

This is an engineering summary of how the project relates to Wazuh's license terms. It is **not legal advice**.
If you plan to redistribute this add-on together with Wazuh, or to ship it inside a commercial product, ask counsel.

## What Wazuh says about its own licensing

From the Wazuh repository (read November 2026):

- The Wazuh engine under `src/engine/` is AGPLv3 or later.
- Shared libraries under `src/shared_modules/` are dual-licensed `GPL-2.0-only OR AGPL-3.0-or-later`.
- "Everything else is licensed under GPLv2", with a special exception permitting linking with OpenSSL.
- The `LICENSE` file adds Wazuh's own interpretation of "derivative work". It lists, as a non-exclusive clarification,
  an application that integrates source code or data files from Wazuh, includes Wazuh copyrighted material, includes
  or integrates Wazuh into a proprietary executable installer, or links to a library or executes a program that does
  any of those things. It also states that these restrictions "only apply if you actually redistribute Wazuh (or parts of it)".
- The README and `LICENSE` do not address separate programs that merely communicate with Wazuh through logs, APIs or
  the agent protocol.

## How this project is built relative to those terms

| Question | Answer |
|---|---|
| Does the repository contain Wazuh source code or data files? | No. The decoders and rules are original XML written for this project, using Wazuh's documented configuration syntax. |
| Does it link to a Wazuh library? | No. It is a standalone Python program. |
| How does it reach Wazuh? | Through the command wodle: the program prints JSON log lines and Wazuh reads them. |
| Does it redistribute Wazuh? | No. Users install Wazuh separately. |
| Runtime dependency | `cryptography` (Apache-2.0 or BSD-3-Clause, dual-licensed). Development-only: `pytest`, `jsonschema`. |
| Vendored third-party files | None. The CycloneDX schemas are downloaded by CI and by the developer when validating, never committed. |

On that basis Apache-2.0 for this repository is a reasonable choice, and nothing in Wazuh's published terms was found
that conflicts with it. The residual uncertainty is the one Wazuh itself leaves open: whether decoder and rule files
that are loaded into a GPL program count as "data files from Wazuh". They contain none of Wazuh's own content. Anyone
who wants certainty before redistributing them inside a Wazuh package should get legal review.

## If you would rather be conservative

Licensing the `wazuh/` directory (decoders, rules, agent snippet) under GPL-2.0 while keeping the Python code under
Apache-2.0 would remove the question for the part that is loaded into Wazuh, at the cost of a mixed-license repository.
