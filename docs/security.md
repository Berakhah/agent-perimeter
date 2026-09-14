# Agent Perimeter Security Policy

## Reporting a vulnerability in Agent Perimeter

If you discover a security vulnerability in Agent Perimeter, please report it directly to <77killuazoldic@gmail.com>. We acknowledge receipt within 24 hours and will provide a clear timeline for remediation or a detailed explanation of why we assess it as not a vulnerability. You may use GitHub private advisories or PGP encryption if desired. Please do not disclose the issue publicly until we have released a fix or made a public statement.

## What we do when we find something in your server

Agent Perimeter sends passive scanning traffic to public MCP servers listed in the official registry. When we identify a finding—a capability edge, configuration exposure, or known vulnerable pattern—we contact the maintainer at the address published in that registry entry or repository. We provide the finding, a reproduction command, and the date by which we intend to publish aggregate statistics on the scanning results.

Our census tier-3 activity sends exactly one unauthenticated `server/discover` JSON-RPC request per sampled host to a random subset of public MCP servers in the registry's remote-only stratum, honours `robots.txt`, respects a maintainer-editable opt-out list, rate-limits itself to one request per second, and identifies itself via a contact URL in the User-Agent header. A host that does not answer is recorded unreachable and never contacted again.

## Embargo

Findings are held in embargo for **90 days** from first contact, giving maintainers time to address issues and release patches. Aggregate statistics—summary counts, pattern frequency, ecosystem distribution—may be published during this period because they identify no specific server. Once the embargo expires:

- Aggregated findings and statistics are published with a digest (salted hash) mapping, so readers can verify the arithmetic without being handed a target list.
- Individual findings remain confidential unless the maintainer consents to attribution.
- No raw data identifying a server is published at any point, before or after the embargo.

## Right of reply

Maintainers may dispute a finding, provide context, or request that we re-run a check against a corrected release. We re-run the check and record the outcome in the changelog regardless of the result. Disputed findings are not published under the maintainer's name unless they explicitly consent to attribution for the historical record.

## Secrets

A credential discovered in a public artifact (registry metadata, package manifest, repository file) is reported to the owner and hosting platform immediately and bypasses embargo entirely. We never publish a raw secret, never include it in raw data, never validate it against a live service, and never expose it in logs, screenshots, or SARIF output. We store only the fingerprint: SHA-256 hash, entropy estimate, prefix, last 4 characters, and source file/line.

## What we publish

We publish aggregate statistics only:

- Ecosystem and distribution summaries (e.g., % of remote-only servers that respond, protocol version adoption).
- Pattern frequency and severity trends across the sampled population.
- Anonymized case studies with digests so reproduction is auditable without target leakage.
- Sample metadata: collection window, method, population size, exclusions (opt-outs, failures), and the salt used for digest generation.

We name no third-party server by registry ID, domain, or maintainer, whether the maintainer replied or not. Raw data is keyed by digest only.

## Digest salt release

The per-run salt used to generate server digests is withheld until the embargo expires. Until then, digests are stable pseudonyms—any reader with the same registry snapshot can verify the arithmetic and confirm that a digest was derived correctly from a server's name—without being handed a target list to probe. Once the embargo expires, the salt is published so historical transparency is complete.
