# Contributing to Secure Code Reviewer

Thank you for helping improve Secure Code Reviewer. The project's priorities, in order, are:
**security accuracy > evidence quality > safe remediation > test coverage > developer experience.**

## Ground rules

- Be honest about capabilities. Do not describe heuristics as complete analysis; document limitations.
- No fabricated data: rules, references and examples must not contain invented CVEs, versions or results.
- Never commit real credentials. Test secrets must be assembled at runtime from fragments (see
  `tests/conftest.py::fake_secret`) and example data must be clearly fictitious.
- Keep runtime scripts dependency-free (Python standard library, 3.9+).
- The scripts must stay read-only against the target, offline by default and never execute target code.

## Development setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
make test validate examples-check
```

## Adding or changing a detection rule

1. Add the rule to `skills/secure-code-reviewer/scripts/rules.py` (`RULES` list). Choose:
   - a precise `pattern` or `matcher`, plus `exclude`/`mitigated_if` to avoid false positives;
   - `needs_input=True` for sinks that are only dangerous with request-derived data;
   - default `severity`, `confidence`, `status` (`Probable` or `Needs Manual Review` — never `Confirmed`);
   - correct `cwe`, `owasp` (and `owasp_api` when relevant) and a remediation `profile` in `P`.
2. Add tests in `tests/test_scanner.py`: at least one vulnerable case **and** one safe look-alike that must
   not be flagged.
3. Ensure `examples/secure-demo` still produces zero findings.
4. If the rule changes demo results, run `make examples` and review the diff of `examples/`.
5. Update `skills/secure-code-reviewer/references/owasp-mapping.md` if you add a new rule family, and `CHANGELOG.md`.

## Changing the findings schema

The schema is a public contract. Additive optional fields are minor changes; anything else requires a new
`schema_version`, updates to `scr_common.validate_document`, `skills/secure-code-reviewer/schemas/findings.schema.json`, tests and the
changelog.

## Pull request checklist

- [ ] `make test`, `make validate` and `make examples-check` pass
- [ ] New rules have vulnerable and safe test cases
- [ ] No real secrets, no generated files outside `examples/`
- [ ] Vulnerable fixtures and demos stay in the root `examples/` or `tests/`, never inside
      `skills/secure-code-reviewer/` (that folder is what users install; `make validate` enforces it)
- [ ] Documentation and `CHANGELOG.md` updated
- [ ] Limitations stated for new capabilities

## Commit messages

Use concise, imperative messages (e.g. `Add SSRF rule for Go net/http`). Reference issues when applicable.

## Code of conduct

Be respectful and constructive. Security research discussion must stay within legal and ethical bounds:
no instructions for attacking systems you are not authorized to test.
