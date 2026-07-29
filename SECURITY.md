# Security Policy

## Supported versions

The latest release (and `main`) is supported. Older versions: update first.

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
private reporting: **Security tab → Report a vulnerability** on this repository.
You'll get an acknowledgment within a few days. No bug bounty; credit given in
the changelog if you want it.

## What counts as a vulnerability here

SentinelHealthCheck is a read-only scanner, but it still has an attack surface
worth reporting:

- **Report injection** — rule names, incident titles, and query text from the
  scanned workspace are attacker-influenced and flow into the HTML report.
  Anything that escapes the HTML encoding is a vulnerability.
- **Credential handling** — the tool holds an Azure access token in memory.
  Anything that writes, logs, or transmits it is a vulnerability.
- **Query/API injection** — workspace content that alters the KQL or ARM
  requests the tool issues.

False findings, scoring disagreements, and feature gaps are ordinary issues —
open those publicly.
