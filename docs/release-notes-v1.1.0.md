# Secure Code Reviewer v1.1.0

Packaging release. The skill's behavior, rules and output schema are unchanged.

## What changed

- The installable skill now lives in `skills/secure-code-reviewer/`. Installing it (with `npx skills add`
  or manually) copies only the skill: instructions, references, scripts, schema and templates.
- The intentionally vulnerable demo applications, sample reports, tests and CI example stay in the
  repository and are no longer copied into your skills directory.

## Upgrading

- `npx skills add titoparra4/secure-code-reviewer@v1.1.0 -g -a claude-code`
- Manual installs: replace the old clone with a copy of `skills/secure-code-reviewer/` (see the README).
- CI users of `examples/ci/secure-code-review.yml`: scripts are now under
  `.scr-tool/skills/secure-code-reviewer/scripts/`.
