# Publishing on GitHub

Content prepared for the repository page and the first release.

## Repository settings

**Description (About):**
> Agent Skill for evidence-based security code review: code, secrets, dependencies, APIs and IaC. Offline, dependency-free tooling with JSON, Markdown and SARIF reports.

**Website:** link to the README or a docs page (optional).

**Topics:**
`agent-skills` `claude-code` `claude-skills` `codex` `security` `appsec` `devsecops` `code-review`
`sast` `secrets-detection` `owasp` `owasp-top-10` `sarif` `security-audit` `supply-chain-security`
`infrastructure-as-code` `github-actions` `python`

**Recommended settings:**
- Enable *Private vulnerability reporting* (Settings → Security) — referenced by `SECURITY.md`.
- Enable Dependabot alerts and secret scanning with push protection.
- Protect `main`: require the `validate` workflow and one review.
- Default workflow permissions: read-only.

## Releasing a version

The installable package is `skills/secure-code-reviewer/`; release archives contain only that folder.

```bash
V=v1.1.0
git tag -a $V -m "Secure Code Reviewer $V"
git push origin $V
gh release create $V --title "Secure Code Reviewer $V" --notes-file docs/release-notes-$V.md
# optional: attach an installable archive for skill upload UIs
git archive --format=zip --prefix=secure-code-reviewer/ -o secure-code-reviewer-$V.zip $V:skills/secure-code-reviewer
gh release upload $V secure-code-reviewer-$V.zip
```

## Release notes (example)

See `docs/release-notes-v1.0.0.md`.
