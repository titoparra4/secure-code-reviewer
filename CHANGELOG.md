# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - Unreleased

### Changed
- The installable skill moved to `skills/secure-code-reviewer/` (SKILL.md, scripts, references, schemas,
  assets, agent metadata, the agent-findings/triage format examples and a copy of the license). The
  intentionally vulnerable demos, sample reports, tests and CI example stay at the repository root, so
  `npx skills add` and manual installs no longer copy vulnerable demo code into the user's skills directory.
  This also removes those demo files from the package that skills.sh security audits (Socket) analyze.
- Manual installation now copies `skills/secure-code-reviewer/` instead of cloning the whole repository
  into the skills directory. The CI example uses `.scr-tool/skills/secure-code-reviewer/scripts/`.
- `validate_skill.py` validates the skill package by default and the surrounding repository with
  `--repo-root`; it fails if vulnerable demos or sample reports end up inside the skill package.

## [1.0.0] - 2026-11-08

### Added
- `SKILL.md` with the eight-phase security review workflow, modes, status rules and safety rules.
- References: methodology, severity/priority/CVSS v4.0 policy, OWASP Top 10:2021 / API Top 10:2023 / ASVS
  mapping, authentication & authorization, secrets, dependencies, infrastructure, remediation and tests,
  API security, CI integration.
- `scan_repository.py`: read-only, offline heuristic scanner with 60+ rules (injection, XSS, CSRF, SSRF,
  path traversal, uploads, deserialization, XXE, mass assignment, prototype pollution, crypto, JWT, cookies,
  misconfiguration, containers, Kubernetes, Terraform, CI/CD, web servers), intra-file taint tracking,
  16 secret detectors with redaction, repository inventory, 7 modes, PR scoping via git diff or file list.
- Dependency parsing for npm, PyPI, Maven, Gradle, NuGet, Go and Cargo manifests/lockfiles; opt-in OSV lookups.
- Optional Semgrep, Gitleaks and Trivy integration (only if installed and requested).
- `normalize_findings.py`: correlation, agent findings, justified triage, baseline-stable `SCR-NNNN` ids.
- `generate_report.py`: Markdown (template-based), JSON and SARIF 2.1.0 output.
- `ci_gate.py`: deterministic, report-only-by-default policy gate with distinct exit codes.
- `validate_skill.py`: package validation for CI and publishing.
- JSON Schema (2020-12) for findings documents.
- Vulnerable and secure demo projects, sample reports, example CI workflow.
- Test suite covering detection accuracy, false-positive prevention, schema validity, id stability,
  redaction, untrusted input handling, absence of side effects and external tool failures.
