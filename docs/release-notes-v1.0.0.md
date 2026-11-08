# Secure Code Reviewer v1.0.0

First public release of **Secure Code Reviewer**, an Agent Skill that turns AI coding assistants into
evidence-based application security reviewers.

## Highlights

- **Eight-phase workflow** (discovery → threat model → static review → correlation → classification →
  remediation → tests → reporting) with progressive-disclosure references.
- **Offline, dependency-free scanner** (Python 3.9+): 60+ heuristic rules across code, auth, crypto,
  containers, Kubernetes, Terraform, CI/CD and web servers; 16 secret detectors with redaction;
  dependency inventory for 7 ecosystems; 7 analysis modes including PR-only scans.
- **Trustworthy results**: candidates are never auto-confirmed; triage requires justification and keeps
  original values; dependency status is `Not Verified` unless an advisory lookup succeeds.
- **Stable identifiers** (`SCR-NNNN`) via line-independent fingerprints and baselines.
- **Reports** in Markdown, JSON (JSON Schema validated) and SARIF 2.1.0.
- **CI gate** that is report-only by default, with distinct exit codes for violations and tool errors, and an
  example least-privilege GitHub Actions workflow.

## Install (Claude Code)

```bash
git clone --depth 1 --branch v1.0.0 https://github.com/titoparra4/secure-code-reviewer.git ~/.claude/skills/secure-code-reviewer
```

See the README for other environments.

## Known limitations

Heuristic analysis (not a full SAST engine); intra-file, name-based taint tracking; no git-history secret
scanning; no automatic reachability analysis for dependencies; CVSS scores are not computed by the scripts.
