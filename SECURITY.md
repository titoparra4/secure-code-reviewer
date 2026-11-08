# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## Reporting a vulnerability

Please **do not open a public issue** for security problems in this project.

Use GitHub's private vulnerability reporting for this repository (**Security → Report a vulnerability**).
If that option is unavailable, open a minimal public issue asking a maintainer for a private contact
channel, without technical details.

Include: affected version/commit, a description of the issue, reproduction steps using fictitious data, and
the impact you expect. We aim to acknowledge reports within 5 business days and to agree on a disclosure
timeline with you.

## Scope

In scope — issues in this repository's code and instructions, for example:

- secrets or sensitive data leaking into reports, logs or SARIF output despite redaction;
- the scanner reading outside the target (path traversal, symlink following) or writing into it;
- execution of code from the audited repository, or command/option injection in tool invocations;
- network access without the explicit opt-in flags;
- `SKILL.md` instructions that could lead an agent to perform unsafe actions (e.g. following instructions
  embedded in audited code).

Out of scope — false positives/negatives of heuristic rules (please open a regular issue with a test case),
and vulnerabilities in third-party tools (Semgrep, Gitleaks, Trivy) or in the intentionally vulnerable
`examples/vulnerable-demo` code.

## Design safeguards

- Read-only, offline-by-default analysis; no execution of target code; no automatic tool installation.
- Redaction of secret values in every evidence snippet; documents with unredacted secret-like values fail validation.
- Symlinks are not followed; file size/count limits; output inside the target requires an explicit flag.
- Git references are validated before use; git runs with hooks and fsmonitor disabled.
- The CI gate prints no evidence, only identifiers and locations.
