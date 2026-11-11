# Secrets Detection

## Contents

1. Detection approach
2. Patterns implemented
3. False-positive controls
4. Redaction rules
5. Classifying secret findings
6. Response playbook (if the secret is or may be real)
7. Prevention

---

## 1. Detection approach

`scan_repository.py` combines:

- **Vendor patterns** with distinctive prefixes (high precision): AWS key ids, GitHub/GitLab/Slack tokens,
  Stripe keys, Google API keys, LLM provider keys, private key headers, JWTs, credentials embedded in
  connection strings.
- **Contextual generic assignments**: a variable/key whose name suggests a secret (`api_key`, `secret`,
  `token`, `password`, `client_secret`, ...) assigned a literal value. Non-password names require length
  ≥ 12 and Shannon entropy ≥ 3.0; password-like names require length ≥ 6.
- **Configuration context**: `.env` files committed, secret-named `ENV`/`ARG` in Dockerfiles, secrets
  echoed in CI logs.
- Optional **Gitleaks** (`--external gitleaks`) for broader coverage; its secret values are never copied.

Limitations: current files only (no git history — use `gitleaks git` or `git log -S` with permission),
no validation against providers (we never call provider APIs to test a key), encoded/split secrets missed.

## 2. Patterns implemented

| Kind | Default severity | Notes |
|---|---|---|
| aws-access-key-id | Medium | Key id alone is not a credential; escalate if a secret key is nearby |
| aws-secret-access-key | Critical | Only when labeled as such |
| github-token / fine-grained PAT | High | Prefix visible after redaction (`ghp_`) |
| gitlab-token | High | |
| slack-token / webhook | High / Medium | |
| stripe-live-key / stripe-test-key | Critical / Low | Test keys reveal account structure but not funds |
| google-api-key | Medium | Often public by design (Maps) when restricted by referrer |
| llm-api-key | High | Billing abuse, data access |
| private-key | High | Only the PEM header is quoted |
| jwt | Medium | May be a sample; check `exp` and signing context |
| connection-string-password | High | Password component redacted only |
| generic-secret-assignment | High (conf. Medium) | Needs triage |

## 3. False-positive controls

Values are ignored when they contain placeholder markers (`example`, `changeme`, `your_`, `<...>`,
`${...}`, `{{...}}`, `xxxx`, `dummy`, `sample`, `redacted`, `os.environ`, `process.env`, ...), consist of
one or two repeated characters, or are references/calls/URLs without credentials. Names ending in `_url`,
`_path`, `_name`, `_type`, `_field`, `_header`, `_id`, ... are not treated as secrets. Files under
`test/`, `fixtures/`, `examples/`, `demo/` keep their findings with confidence lowered one level.

When triaging, a candidate is a **False Positive** only if you can explain why the value is not a usable
credential (documented test fixture, public identifier, revoked and documented, generated placeholder).

## 4. Redaction rules

- Reports contain `[REDACTED:<kind>:len=<n>]` in place of the value. Only a **public vendor prefix**
  (`ghp_`, `AKIA`, `sk_live_`, `xoxb-`, ...) may remain, because it identifies the credential type without
  revealing secret material.
- No hash of the secret is stored: hashes of low-entropy passwords are brute-forceable. Findings are
  identified by their SCR id and fingerprint (computed on redacted evidence).
- `sanitize_text()` is applied to **every** snippet, not just secret findings, so a secret on the same line
  as an SQL injection is still redacted. `validate_document()` rejects documents containing unredacted
  secret-like values.
- In chat, never print the full value, even if the user asks — tell them the file and line instead.

## 5. Classifying secret findings

Ask:
1. Is it a real credential format with plausible entropy? Provider prefix + correct length → likely real.
2. What can it access (production vs sandbox, scopes, admin rights)?
3. Where is it exposed (public repo, private repo, built image, client-side bundle)?
4. Is it in history even if removed from HEAD?

Map: production credential with broad privileges in a public or widely shared repo → Critical; production
credential in a private repo → High; limited-scope or sandbox → Medium/Low; likely fake → Needs Manual Review
with Low confidence.

## 6. Response playbook

Recommend, in this order:
1. **Revoke or rotate** the credential at the provider (removing it from code does not invalidate it).
2. **Review usage logs** at the provider for the exposure window (CloudTrail, GitHub audit log, Stripe logs).
3. **Replace** with a secret-manager or environment lookup (`os.environ["X"]`, Vault, AWS Secrets Manager,
   Azure Key Vault, GCP Secret Manager, Kubernetes Secrets with encryption at rest).
4. **Purge from history** only after rotation (git filter-repo / BFG), coordinating with the team, since it
   rewrites history.
5. **Prevent recurrence** (section 7).

## 7. Prevention

- Pre-commit secret scanning (e.g. gitleaks pre-commit hook) and CI scanning (this skill's `--mode secrets`
  in report-only or blocking mode).
- Provider-side push protection (e.g. GitHub secret scanning push protection) where available.
- `.env` in `.gitignore`; commit `.env.example` with placeholders.
- Short-lived credentials (OIDC federation for CI, IAM roles) instead of static keys.
