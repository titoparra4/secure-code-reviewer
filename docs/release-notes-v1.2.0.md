# Secure Code Reviewer v1.2.0

Security hardening release. Detection rules and the output schema are unchanged; one new informational
finding (`meta.scanner-suppression-file`) was added.

## What changed

- **Least-privilege tools.** `SKILL.md` now declares `allowed-tools`: only `Read`, `Grep`, `Glob` and the
  three pipeline scripts (`scan_repository.py`, `normalize_findings.py`, `generate_report.py`) are
  pre-approved. Writing triage files and applying Remediation Mode patches (`Edit`/`Write`) always asks you.
- **The audited repository cannot silence external tools.** With `--external`:
  - semgrep runs with `--disable-nosem`, plus `--x-ignore-semgrepignore-files` when your version supports it;
  - gitleaks uses the skill's own `assets/gitleaks.toml` (default rules, no repository allowlists),
    `--ignore-gitleaks-allow` and an empty `--gitleaks-ignore-path`;
  - trivy uses an empty `--ignorefile`.
- **Suppression files are reported.** `.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore` and `.trivyignore`
  at the target root produce an informational `meta.scanner-suppression-file` finding. Gitleaks 8.x always
  loads `<target>/.gitleaksignore`, so review that file when it appears.
- **Informed consent for network access.** The skill tells you that semgrep (`p/default`) and trivy download
  rules and databases. For an offline semgrep run, pass `--semgrep-config /path/to/rules.yml`.
- **Supply chain.** GitHub Actions in the CI example are pinned to full commit SHAs. Development
  dependencies are pinned to exact versions.

## Upgrading

- `npx skills add titoparra4/secure-code-reviewer@v1.2.0 -g -a claude-code`
- Manual installs: replace your copy of `skills/secure-code-reviewer/` (it now includes `assets/gitleaks.toml`).
- CI users of `examples/ci/secure-code-review.yml`: set `SCR_REF: v1.2.0` and copy the pinned `uses:` lines.
- If you relied on `nosem` comments, `.semgrepignore`, `gitleaks:allow` or a repository `.gitleaks.toml` to
  hide results, those results now appear. Record the decisions in a triage file (`--triage`) instead.
