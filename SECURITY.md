# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.2.x | Yes |
| 1.1.x | No — upgrade to 1.2.x |
| 1.0.x | No — upgrade to 1.2.x |

Only the latest minor release receives security fixes. 1.2.0 introduced the `allowed-tools` restriction and the
anti-suppression flags for external scanners; earlier versions lack them and will not get backports.

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

## Threat model

This repository ships an agent skill, not an agent: it runs inside a host (Claude Code, Codex) and has no
agent loop, identity or manifest of its own. It reads untrusted code by design.

### Trust boundaries

- **Untrusted:** everything from the audited repository — code, comments, docs, configs, commit messages —
  and the output of tools run on it.
- **Trusted:** this skill (`SKILL.md`, references, schemas, assets) and its scripts.
- **Host:** everything else (see *Host responsibilities*).

### Mitigations in this repository

- Read-only, offline-by-default static analysis; the target's code and tests are never executed.
- `allowed-tools` in `SKILL.md` pre-approves only `Read`, `Grep`, `Glob` and `Bash` for the three pipeline
  scripts (`scan_repository.py`, `normalize_findings.py`, `generate_report.py`). `Edit` and `Write` are not
  pre-approved, so every write needs explicit user approval.
- External tools (`scripts/external_tools.py`) run with argument lists (no shell) and a timeout, and with
  flags that stop the target from silencing them: semgrep `--disable-nosem` (plus
  `--x-ignore-semgrepignore-files` when supported); gitleaks with the skill's own `assets/gitleaks.toml`,
  `--ignore-gitleaks-allow` and an empty `--gitleaks-ignore-path`; trivy with an empty `--ignorefile`.
- Suppression files in the target root (`.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`,
  `.trivyignore`) are reported as `meta.scanner-suppression-file` (gitleaks 8.x still loads
  `<target>/.gitleaksignore`).
- Network access only with explicit flags: `--external` (semgrep with the default `p/default` downloads
  rules from semgrep.dev; trivy downloads its databases; gitleaks is offline) and `--osv` (sends package
  names/versions to api.osv.dev).

### Residual risk: prompt injection

The audited content can contain instructions aimed at the agent. The rules in `SKILL.md` that say to treat it
as data and never follow it are **instructions to the model, not a technically enforced control**. Nothing in
this repository prevents a model from obeying injected text. The `meta.prompt-injection-marker` rule is a
regex heuristic that flags a few common phrasings; it detects, it does not block, and it misses rewordings.
This risk is open and is not mitigated by this repository.

### Host responsibilities

The host controls the permission mode and approvals, the execution sandbox, iteration limits, identity and
credentials, network egress and MCP servers. This skill cannot enforce any of them.

- Do not audit untrusted repositories with broad auto-approval modes or with sensitive credentials (cloud,
  registry, Git tokens) in the environment.
- The `*` wildcards in `allowed-tools` pre-approve **any** arguments to the three scripts, including
  `--external`, `--osv`, `-o` (any output path; only `scan_repository.py` refuses paths inside the target
  unless `--allow-write-in-target` is passed) and `--allow-write-in-target`. If that
  matters in your setting, restrict them with your host's own permission settings.

## Agent security audit

Run `make agent-audit` (requires `agent-security-auditor`; policy and scope in
[`.security/agent-audit-policy.yaml`](.security/agent-audit-policy.yaml)).

- Exit **30** (`INSUFFICIENT_EVIDENCE`) is expected and accepted: there is no agent manifest because the agent
  belongs to the host. An honest manifest fails CTRL-PI-01 (see *Residual risk*); one that passes would
  declare controls that belong to the host.
- Exit **20** (`NOT_READY`) or **70** (scanner error) is a regression.
- The policy's false-positive exceptions for `tests/` expire on **2027-05-17**; review them before then
  (expired exceptions are ignored).

## Design safeguards

- No automatic installation of external tools.
- Redaction of secret values in every evidence snippet; documents with unredacted secret-like values fail validation.
- Symlinks are not followed; file size/count limits; `scan_repository.py` refuses output inside the target without
  `--allow-write-in-target` (`normalize_findings.py` and `generate_report.py` do not restrict `-o`).
- Git references are validated before use; git runs with hooks and fsmonitor disabled.
- The CI gate prints no evidence, only identifiers and locations.
