# Remediation and Security Test Guidelines

## Contents

1. Principles
2. Remediation workflow (Remediation Mode)
3. Fix patterns by vulnerability class
4. Writing safe security tests
5. Regression tests and behavior preservation
6. Agent findings and triage file formats

---

## 1. Principles

- **Explicit authorization**: present the patch and tests; apply only after the user approves. Never commit
  or push unless asked.
- **Minimal and behavior-preserving**: change the smallest surface that removes the root cause; keep
  public interfaces and legitimate behavior.
- **Fix the root cause**, not the symptom (parameterize queries rather than escaping quotes; enforce
  authorization in the data access, not only the UI).
- **Defense in depth** is a complement, not a substitute (a WAF does not fix SQLi).
- **Prefer framework/library primitives** over custom sanitizers.
- **Verify**: every fix comes with a reproduction test (fails before, passes after) and a regression test
  for legitimate behavior.

## 2. Remediation workflow

For each selected finding (start with P1):

1. Re-read the code and confirm the finding is still present (code may have changed).
2. Explain the problem in one paragraph: source → sink, missing control.
3. Propose the fix as a unified diff or a replacement snippet, with file and line references.
4. Provide the security test and the regression test (section 4–5), in the project's test framework.
5. List side effects (migrations, config changes, client changes, performance).
6. After approval: apply, run the tests (if the user permits running them), and report the actual results.
   If tests were not run, say "not executed".
7. Update the finding: keep it in the report with a note, or remove it on re-scan; with `--baseline` it will
   appear in `resolved_ids`.

## 3. Fix patterns

| Class | Fix |
|---|---|
| SQL injection (CWE-89) | Parameterized queries / ORM; allow-list for dynamic identifiers |
| Command injection (CWE-78) | Argument arrays without shell; allow-list validation; native libraries |
| Code injection (CWE-95) | Remove eval; parse data formats; dispatch tables |
| SSTI (CWE-1336) | Render fixed templates; user data only in context |
| XSS (CWE-79) | Auto-escaping; `textContent`; sanitizer (DOMPurify) for rich HTML; CSP |
| Path traversal (CWE-22) | Resolve + verify containment; opaque ids; `send_from_directory`/`secure_filename` |
| Uploads (CWE-434) | Server-generated names; content-type sniffing; size limits; storage outside web root |
| SSRF (CWE-918) | Host/scheme allow-list; block private/link-local after DNS resolution; no redirects |
| Deserialization (CWE-502) | JSON / safe loaders; signed payloads; type allow-lists |
| XXE (CWE-611) | Disable DTDs/external entities; `defusedxml` |
| Mass assignment (CWE-915) | DTOs/schemas with explicit fields |
| IDOR (CWE-639) | Scope queries by owner/tenant; central authorization helpers |
| CSRF (CWE-352) | Framework CSRF tokens; SameSite cookies |
| JWT (CWE-347/613) | Verify signature with pinned algorithms; validate exp/iss/aud |
| Weak password hashing (CWE-916) | Argon2id/bcrypt/scrypt with rehash-on-login migration |
| Insecure randomness (CWE-338) | `secrets`, `crypto.randomBytes`, `SecureRandom`, `RandomNumberGenerator` |
| TLS validation (CWE-295) | Remove `verify=False`; custom CA bundle if needed |
| Secrets (CWE-798) | Rotate → move to secret manager → purge history |
| Containers (CWE-250) | Non-root, drop capabilities, no privilege escalation, no host namespaces/socket |
| IaC exposure | Private networking, block public access, encryption, least-privilege IAM |
| CI injection (CWE-94) | `env:` indirection, least-privilege `permissions`, SHA-pinned actions |

## 4. Safe security tests

Security tests must be **local, deterministic and non-destructive**:

- Run against test doubles, an in-memory/ephemeral database, or a local instance — never against shared or
  production systems.
- Use benign payloads that prove the behavior without causing harm: `' OR '1'='1` against a test DB;
  `;id` with subprocess mocked; `../../etc/passwd` asserting a 400/404; `http://169.254.169.254/` with the
  HTTP client mocked; `<img src=x onerror=alert(1)>` asserting escaped output.
- Do not include working exploit chains against third-party software, malware, or payloads that delete data.
- Assert on observable outcomes: status code, absence of data, escaped output, mock not called / called with
  safe arguments.

Example (pytest, Flask, SQLi):
```python
def test_find_user_rejects_sql_injection(client, seeded_db):
    resp = client.get("/users", query_string={"email": "' OR '1'='1"})
    assert resp.status_code == 200
    assert resp.get_json() == []           # payload treated as a literal
```

Example (IDOR, two users):
```python
def test_user_cannot_read_other_users_invoice(client, alice, bob, bob_invoice):
    login(client, alice)
    assert client.get(f"/invoices/{bob_invoice.id}").status_code == 404
```

## 5. Regression tests

- Legitimate inputs still produce the same results (same rows, same response shape, same status codes).
- Edge cases that the fix might break: unicode, empty values, maximum lengths, legacy data (e.g. old
  password hashes must still allow login while being upgraded).
- Run the existing test suite; report pass/fail counts honestly. If the suite cannot run, say so.

## 6. File formats

### Agent findings (`--add`)
See `examples/agent-findings.json`. Required: `title, severity, confidence, status, cwe, owasp_category,
location{file,start_line,end_line}, evidence{description,sanitized_code}, impact, remediation{recommendation,
verification}`. Optional: `rule_id, category, owasp_api_category, exploitability, business_impact,
remediation.fixed_code_example/security_test/regression_test, effort, cvss, references, verification`.
Optional top-level `coverage` list records categories you actually reviewed:
`{"category": "...", "status": "reviewed|partial|not_reviewed", "method": "manual", "notes": "..."}`.

### Triage (`--triage`)
See `examples/triage.json`. Each entry matches by `fingerprint` (preferred, stable), by `rule_id` + `file`
(+ optional `line`), or by `id` of the input scan. Every entry needs `justification` (≥ 10 characters);
optional `status`, `severity`, `confidence`, `reviewer`, `reproduced`. Originals are kept in `triage`.
