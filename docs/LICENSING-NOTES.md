# Licensing notes

This is an engineering summary, **not legal advice**. If you plan to redistribute this add-on together with a SIEM
platform, or to ship it inside a commercial product, ask counsel.

## How this project relates to the SIEM platform it feeds

Open-source SIEM platforms are typically licensed under GPL-2.0 or AGPL-3.0, sometimes with their own clarification of
what counts as a derivative work. Such clarifications usually restrict redistribution of the platform or of its code and
data files, and say little about separate programs that only exchange logs with it.

| Question | Answer for this repository |
|---|---|
| Does it contain the platform's source code or data files? | No. The decoders and rules are original XML written for this project, using the platform's documented configuration syntax. |
| Does it link to a platform library? | No. It is a standalone Python program. |
| How does it reach the platform? | Through the agent's command module: the program prints JSON log lines and the platform reads them. |
| Does it redistribute the platform? | No. Users install the platform separately. |

## Conclusion

Apache-2.0 for this repository is a reasonable choice, and nothing in the published terms read in November 2026 was
found to conflict with it. The residual uncertainty is the one the platform's own license leaves open: whether decoder
and rule files loaded into a GPL program count as its "data files". They contain none of its content. Anyone who wants
certainty before redistributing them inside a platform package should get legal review.

## Option

Licensing the `siem/` directory (decoders, rules, agent snippet) under GPL-2.0 while keeping the Python code under
Apache-2.0 would remove the question for the part loaded into the platform, at the cost of a mixed-license repository.
