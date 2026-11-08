# Secure Code Reviewer

**An open-source Agent Skill for evidence-based application security reviews — with offline, dependency-free tooling that produces validated JSON, Markdown and SARIF reports.**

[![validate](https://github.com/titoparra4/secure-code-reviewer/actions/workflows/validate.yml/badge.svg)](https://github.com/titoparra4/secure-code-reviewer/actions/workflows/validate.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)

Secure Code Reviewer turns an AI coding assistant (Claude Code, OpenAI Codex and other environments that support
the `SKILL.md` format) into a disciplined security reviewer. It does not just list generic vulnerability
types: every finding is tied to a file and line, carries sanitized evidence, a calibrated severity and
confidence, an explicit verification status, a fix, a safe security test and a regression test.

> **Honest scope.** The bundled scanner is a heuristic, pattern-and-context engine (with intra-file
> taint tracking). It is **not** a full SAST engine. It produces *candidates* that the agent triages
> by reading the code. It can integrate Semgrep, Gitleaks and Trivy when they are installed.

---

## Table of contents

- [Features](#features)
- [Example report](#example-report)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Analysis modes](#analysis-modes)
- [Output format](#output-format)
- [CI/CD integration](#cicd-integration)
- [Limitations](#limitations)
- [Security and privacy](#security-and-privacy)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Features

| Area | What it covers |
|---|---|
| **Code analysis** | SQL/NoSQL/command/code injection, SSTI, XSS, CSRF, SSRF, open redirect, path traversal, unsafe uploads, insecure deserialization, XXE, mass assignment, prototype pollution, weak crypto, insecure randomness, TLS validation, error disclosure, sensitive logging, insecure temp files. Python, JavaScript/TypeScript, Java/Kotlin, C#, PHP, Go, Ruby. |
| **Agent review** | Broken access control / IDOR, authorization policies (RBAC/ABAC), business logic, race conditions, authentication flows — guided by the methodology in `references/`. |
| **Secrets** | 16 detectors (vendor-prefixed tokens, private keys, JWTs, connection strings, contextual generic assignments) with placeholder/entropy filtering. **Values are never written to any report.** |
| **AuthN / AuthZ** | JWT signature/algorithm/claims validation, cookie flags, password storage, session handling, OAuth/OIDC review checklist. |
| **Dependencies** | Parses 14 manifest/lockfile formats (npm, PyPI, Maven, Gradle, NuGet, Go, Cargo). Offline: pinning, wildcards, VCS sources. Opt-in OSV lookups for known vulnerabilities — never invented CVEs; unknown = **Not Verified**. |
| **Infrastructure** | Dockerfile, Compose, Kubernetes, Terraform (AWS/Azure/GCP), GitHub Actions, GitLab CI, Azure Pipelines, Nginx/Apache, app config and `.env` files. |
| **Remediation** | Fix recommendations, corrected code examples, safe reproduction tests and regression tests; changes are applied only with explicit authorization. |
| **Reporting** | Executive summary, findings table, detailed findings, coverage, dependency table, remediation roadmap (P1–P4). Markdown, JSON (JSON Schema validated) and SARIF 2.1.0. |
| **Traceability** | Stable `SCR-NNNN` ids via line-independent fingerprints and baselines; triage decisions keep original values and require justification. |
| **DevSecOps** | Deterministic CI gate (report-only by default), baseline comparison, distinct exit codes for vulnerabilities vs tool errors, least-privilege workflow example. |

## Example report

Generated from [`examples/vulnerable-demo`](examples/vulnerable-demo) (full report: [`examples/sample-review.md`](examples/sample-review.md), JSON: [`examples/sample-report.json`](examples/sample-report.json), SARIF: [`examples/sample-report.sarif`](examples/sample-report.sarif)):

```text
## 1. Executive Summary
Scope. Target `examples/vulnerable-demo` in `full` mode; 11 files analyzed, 0 skipped.
Risk summary. Highest severity among Confirmed/Probable findings: High. Active findings: 42 ...
```

| ID | Severity | Finding | File | Confidence | Status | Priority |
|---|---|---|---|---|---|---|
| SCR-0001 | High | Credentials in database/broker connection string | `app/app.py:17` | High | Probable | P1 |
| SCR-0002 | High | SQL query built with string interpolation | `app/app.py:29` | High | Probable | P1 |
| SCR-0003 | High | Insecure Direct Object Reference on invoice retrieval | `app/app.py:41-46` | High | Confirmed | P1 |
| SCR-0004 | High | OS command execution through a shell | `app/app.py:52` | High | Probable | P1 |

Evidence is always sanitized:

```text
DATABASE_URL = "postgresql://demo_user:[REDACTED:connection-string-password:len=17]@db.internal:5432/shop"
```

`SCR-0003` (IDOR) was added by the agent's manual review (`examples/agent-findings.json`), something no
pattern rule can detect; a weak-hash candidate used only for a cache key was triaged as a False Positive
with a written justification (`examples/triage.json`).

## Architecture

```text
             ┌──────────────── SKILL.md (workflow, rules, modes) ───────────────┐
             │   loads references/*.md on demand (progressive disclosure)       │
             └───────────────────────────────┬──────────────────────────────────┘
                                             │ agent runs (read-only, offline)
 target repo ──► scripts/scan_repository.py ─┴─► candidates (stage: scan)
                   rules.py · dependency_parsers.py · external_tools.py (optional)
                                             │
 agent triage + manual review ──► agent-findings.json / triage.json
                                             │
                 scripts/normalize_findings.py  (correlate · triage · baseline ids)
                                             │  validated against schemas/findings.schema.json
                 scripts/generate_report.py ──► Markdown · JSON · SARIF
                 scripts/ci_gate.py ─────────► exit 0 / 1 (policy) / 2 (tool error)
```

```text
secure-code-reviewer/
├── SKILL.md                    # skill entry point (frontmatter + operating instructions)
├── agents/openai.yaml          # optional UI metadata for OpenAI Codex
├── references/                 # methodology, severity, OWASP/ASVS mapping, topic guides
├── scripts/                    # stdlib-only Python tooling
├── schemas/findings.schema.json
├── assets/report-template.md
├── examples/                   # vulnerable + secure demos, sample reports, CI workflow
├── tests/                      # pytest suite (detection, schema, ids, reports, safety)
└── .github/workflows/validate.yml
```

## Requirements

- An assistant that supports Agent Skills (`SKILL.md`), **or** any environment where you can provide the
  instructions manually (see below).
- To run the tooling: **Python 3.9+**, no third-party packages. Tests need `pytest` and `jsonschema`
  (`requirements-dev.txt`).
- Optional: Semgrep, Gitleaks, Trivy (used only if installed and requested); network access only for the
  opt-in `--osv` lookup.

## Installation

The skill folder must be named `secure-code-reviewer` (the skill `name`).

### Claude Code

Personal (available in all projects):

```bash
git clone --depth 1 --branch v1.0.0 https://github.com/titoparra4/secure-code-reviewer.git \
  ~/.claude/skills/secure-code-reviewer
```

Project-scoped (shared with your team through the repository):

```bash
git clone --depth 1 --branch v1.0.0 https://github.com/titoparra4/secure-code-reviewer.git \
  .claude/skills/secure-code-reviewer
```

Claude Code discovers skills in these directories automatically; ask *"Review this repository for
security vulnerabilities"* or *"What skills are available?"* to confirm.

### Claude apps (claude.ai / desktop)

Where custom skills are enabled for your plan, upload the skill as a ZIP whose top-level folder is
`secure-code-reviewer/` (Settings → Capabilities/Skills at the time of writing; code execution must be
enabled for the scripts):

```bash
git archive --format=zip --prefix=secure-code-reviewer/ -o secure-code-reviewer.zip v1.0.0
```

### OpenAI Codex

Codex supports skills in the same `SKILL.md` format. Copy or clone the folder into the skills directory
documented for your Codex version (check the current Codex documentation; user-level skills have lived
under `~/.codex/skills/`). `agents/openai.yaml` supplies optional display metadata.

### ChatGPT and other assistants

Skill support differs between ChatGPT plans and interfaces and changes over time; check whether your
workspace offers skills. If it does not:

1. Provide `SKILL.md` as instructions (e.g. a Project's instructions or a custom GPT), and upload the
   `references/` files as knowledge files.
2. To use the scripts, upload the repository ZIP in a conversation with code execution (Python) enabled
   and ask the assistant to run `scripts/scan_repository.py`; they need only the standard library.
3. Without code execution, the assistant follows the "Reviewing without tooling" procedure in
   `references/security-methodology.md`.

### Third-party skill installers

Community CLIs such as `npx skills add titoparra4/secure-code-reviewer` can install skills from GitHub.
They are not maintained by this project; review what they install.

### Verify the installation

```bash
cd secure-code-reviewer
python3 scripts/validate_skill.py
python3 scripts/scan_repository.py examples/vulnerable-demo --mode quick -o /tmp/scr-check.json
```

## Usage

### With an assistant

Natural-language prompts map to modes automatically:

- "Review this repository for security vulnerabilities." → Full Security Audit
- "Audit authentication and authorization." → focused review (`authentication-security.md`)
- "Check this pull request for security risks." → Pull Request Review
- "Find exposed secrets." → Secrets Scan
- "Review my .NET APIs for OWASP vulnerabilities." → API Security Review
- "Analyze my Docker and Kubernetes security." → configuration review
- "Generate secure fixes for critical findings." → Remediation Mode (patches proposed, applied only on approval)
- "Create security regression tests." → tests for selected findings
- "Export the security report as JSON." → `generate_report.py -f json`

### Command line

```bash
# 1. scan (read-only, offline); write outputs outside the scanned tree
python3 scripts/scan_repository.py /path/to/repo --mode full -o /tmp/scr-raw.json

# 2. merge agent findings, apply triage, keep ids stable against a baseline
python3 scripts/normalize_findings.py /tmp/scr-raw.json \
  --add agent-findings.json --triage triage.json --baseline baseline.json -o /tmp/scr-report.json

# 3. render
python3 scripts/generate_report.py /tmp/scr-report.json -f markdown -o /tmp/scr-report.md
python3 scripts/generate_report.py /tmp/scr-report.json -f sarif    -o /tmp/scr-report.sarif

# 4. gate (report-only unless --fail-on is set)
python3 scripts/ci_gate.py --report /tmp/scr-report.json --fail-on high
```

Useful scanner options: `--mode pr --git-diff origin/main`, `--changed-files-from FILE`,
`--exclude 'vendor/*'`, `--max-file-bytes`, `--max-files`, `--osv` (network, opt-in),
`--external semgrep,gitleaks,trivy`, `--semgrep-config p/default`.

## Analysis modes

| Mode | Flag | Scope |
|---|---|---|
| Quick Scan | `--mode quick` | secrets, configuration, High/Critical code rules |
| Full Security Audit | `--mode full` | all rules + dependency inventory |
| Pull Request Review | `--mode pr` | all rules on changed files (+ agent reviews needed context) |
| API Security Review | `--mode api` | code, auth, API and secrets rules; OWASP API Top 10 mapping |
| Secrets Scan | `--mode secrets` | secret detectors only |
| Dependency Audit | `--mode dependencies` | manifests/lockfiles; `--osv` to verify advisories |
| Configuration review | `--mode config` | Docker, K8s, Terraform, CI, web servers, app config |
| Remediation Mode | (agent) | fixes + tests for selected findings, applied only with authorization |
| Compliance Mapping | (agent) | CWE / OWASP / ASVS mapping — never a compliance claim |

## Output format

Every document validates against [`schemas/findings.schema.json`](schemas/findings.schema.json)
(JSON Schema 2020-12). A finding looks like:

```json
{
  "id": "SCR-0002",
  "fingerprint": "1573357b88c79be42f57994c3d2285b0",
  "rule_id": "injection.sql.string-built-query",
  "title": "SQL query built with string interpolation",
  "severity": "High",
  "confidence": "High",
  "status": "Probable",
  "cwe": "CWE-89",
  "owasp_category": "A03:2021-Injection",
  "location": {"file": "app/app.py", "start_line": 29, "end_line": 29},
  "evidence": {"description": "…", "sanitized_code": "cur.execute(f\"SELECT id, email FROM users WHERE email = '{email}'\")"},
  "impact": "…", "exploitability": "…", "business_impact": "…",
  "remediation": {"recommendation": "…", "fixed_code_example": "…", "security_test": "…",
                  "regression_test": "…", "verification": "…"},
  "remediation_priority": "P1", "effort": "Low", "source": "scanner",
  "verification": {"method": "heuristic", "reproduced": false, "notes": ["…"]},
  "cvss": null
}
```

Statuses: `Confirmed` (agent/human only), `Probable`, `Needs Manual Review`, `False Positive` (justified),
`Not Verified`. Severity levels, confidence, priorities and the CVSS v4.0 policy are defined in
[`references/severity-classification.md`](references/severity-classification.md).

## CI/CD integration

Copy [`examples/ci/secure-code-review.yml`](examples/ci/secure-code-review.yml) into your repository's
`.github/workflows/`. It runs the deterministic pipeline on pull requests (changed files) and on `main`
(full scan), uploads SARIF to code scanning, stores the report as an artifact and runs the gate.

- **Least privilege**: `contents: read`; `security-events: write` only for SARIF upload; `persist-credentials: false`.
- **Report-only by default**; set `FAIL_ON` to block. Only `Confirmed`/`Probable` findings at or above the
  threshold block; unverified findings never block unless you add their statuses.
- **Baselines**: commit `.security/baseline.json` to fail only on new findings; ids of existing findings stay stable.
- **Exit codes**: `0` pass, `1` policy violation, `2` invalid input/tool error.
- **No secrets in logs**: the gate prints ids, titles and locations only.

Running an AI agent inside CI is possible but should be advisory only (non-deterministic, exposed to prompt
injection from PR content). See [`references/ci-integration.md`](references/ci-integration.md).

## Limitations

- Heuristic rules and name-based, intra-file taint tracking produce both false positives and false
  negatives; cross-file data flow, framework-specific sanitizers and runtime configuration are not modeled.
- Authorization, IDOR and business logic depend on the agent's (or your) manual review.
- Dependency vulnerability status is **Not Verified** unless `--osv` (or an external tool) succeeds;
  reachability is never assessed automatically.
- Secrets detection covers the working tree, not git history.
- CVSS v4.0 scores are not computed by the scripts; vectors are recorded only when justified.
- No result is a guarantee of absence of vulnerabilities or a compliance attestation.

## Security and privacy

- Scripts are **read-only** against the target, never execute its code, skip symlinks and oversized/binary
  files, and refuse to write output inside the scanned tree unless `--allow-write-in-target` is passed.
- **Offline by default.** `--osv` sends only package names, versions and ecosystems to `api.osv.dev`.
  External tools run only if installed and requested; nothing is installed automatically.
- Secrets are redacted in every snippet (`[REDACTED:kind:len=N]`); no hashes of secret values are stored;
  documents containing unredacted secret-like values fail validation.
- Repository content is treated as untrusted data; embedded instructions aimed at AI agents are reported,
  not followed.
- Vulnerable examples use fictitious data only.

Report vulnerabilities in this project as described in [SECURITY.md](SECURITY.md).

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
make test            # pytest suite
make validate        # skill package validation
make examples        # regenerate sample reports (reproducible)
make examples-check  # CI: verify committed examples match the implementation
```

## Contributing

Contributions are welcome — new rules with vulnerable and safe test cases, parsers, references and fixes.
Read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

[MIT](LICENSE)
