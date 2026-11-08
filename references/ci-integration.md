# CI/CD Integration

## Contents

1. Two integration models
2. Deterministic pipeline (recommended)
3. Baselines and "new findings only"
4. Gate policy and exit codes
5. Running an AI agent in CI: limitations
6. Hardening the pipeline itself

---

## 1. Two integration models

| Model | What runs | Pros | Cons |
|---|---|---|---|
| **Deterministic** (recommended for gating) | `scan_repository.py` + optional Semgrep/Gitleaks/Trivy + `ci_gate.py` | reproducible, fast, no model cost, no data leaves the runner (offline by default) | heuristic; no reasoning about authorization or logic |
| **Agent-assisted** (advisory) | an AI coding agent with this skill reviews the PR and comments | deeper triage, logic/authz review | non-deterministic, cost, requires API keys, prompt-injection exposure, needs human review |

Use the deterministic model to gate merges and the agent-assisted model for advisory review comments.

## 2. Deterministic pipeline

A ready-to-copy workflow is in `examples/ci/secure-code-review.yml`. Steps:

1. Checkout with `persist-credentials: false`.
2. Compute changed files for PRs: `git diff --name-only --diff-filter=ACMR origin/<base>...HEAD`.
3. `scan_repository.py . --mode pr --changed-files-from changed.txt -o $RUNNER_TEMP/scr-raw.json`
   (or `--mode full` on the default branch / schedule).
4. `normalize_findings.py ... --baseline .security/baseline.json` (optional) and `--triage .security/triage.json`.
5. `generate_report.py` → Markdown (job summary / artifact) and SARIF (code scanning upload).
6. `ci_gate.py` with the team's policy.

Write outputs to `$RUNNER_TEMP`, not the workspace (the scanner refuses to write inside the scanned tree
without `--allow-write-in-target`).

## 3. Baselines

- Generate once on the default branch: `normalize_findings.py raw.json -o .security/baseline.json`, review it,
  commit it.
- In PRs: `normalize_findings.py raw.json --baseline .security/baseline.json` marks findings `new`/`existing`
  and lists `resolved_ids`; ids of existing findings never change.
- Gate on new findings only: `ci_gate.py --report report.json --fail-on high --only-new`.
- Refresh the baseline deliberately (reviewed PR), never automatically from a PR branch.

## 4. Gate policy

`ci_gate.py` defaults to **report-only** (`--fail-on none`). Teams opt into blocking:

```bash
python scripts/ci_gate.py --report report.json --fail-on high --statuses Confirmed,Probable \
  --min-confidence Medium --only-new
```

| Exit code | Meaning | Suggested CI handling |
|---|---|---|
| 0 | policy passed | continue |
| 1 | policy violated | fail the check (vulnerabilities) |
| 2 | invalid input / tool error (with `--fail-on-tool-error`) | fail as infrastructure error, not as a vulnerability |

Findings with status `Needs Manual Review` or `Not Verified` do not block unless explicitly added to
`--statuses`. Gate output contains ids, titles, files and lines only (no evidence), so logs cannot leak
secrets.

## 5. AI agents in CI — limitations

- **Prompt injection**: PR content is attacker-controlled. Never give the agent write tokens, deployment
  credentials or secrets when reviewing untrusted PRs (especially from forks). Run with read-only
  `permissions` and post comments through a separate, minimal step.
- **Non-determinism**: results can vary between runs; do not use agent output as a hard gate.
- **Data handling**: sending code to a model provider must be approved by the organization.
- **Cost/latency**: restrict to changed files (`--mode pr`) and to labeled PRs if needed.
- **Verification**: agent findings must be reviewed by a human before being treated as Confirmed.

## 6. Hardening the pipeline

- `permissions: contents: read` at workflow level; add `security-events: write` only to the SARIF upload job.
- Use `pull_request` (not `pull_request_target`) for scanning PR code.
- Pin actions to commit SHAs in your organization (the example uses version tags for readability; replace them
  with SHAs you verify).
- Never print reports containing evidence to logs for public repositories; upload as artifacts with
  restricted retention, or rely on SARIF.
- External tools are optional: if they are not installed, the scan still completes and records the gap.
