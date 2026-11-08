# Severity, Confidence, Status and Priority

## Contents

1. Severity levels
2. Context modifiers
3. Confidence
4. Status (verification state)
5. Remediation priority (P1–P4)
6. CVSS v4.0 methodology
7. Exploitability and business impact
8. Worked examples

---

## 1. Severity levels

Severity estimates the **impact × likelihood** of the issue *in this codebase's realistic context*.

| Severity | Definition | Typical examples |
|---|---|---|
| **Critical** | Remote, unauthenticated (or trivially obtained access) compromise of the system, its data or infrastructure, with low attack complexity. | Pre-auth RCE; SQLi on a public endpoint exposing all data; live cloud admin credentials in a public repo; JWT signature not verified on all APIs. |
| **High** | Significant compromise requiring some precondition (authenticated low-privileged user, specific configuration), or broad data exposure. | Authenticated SQLi; IDOR on sensitive records; SSRF to internal network; privileged container; hardcoded production DB password. |
| **Medium** | Real risk under specific conditions, limited scope, or defense-in-depth failure on a sensitive path. | Reflected XSS with CSP gaps; CSRF on non-critical state change; weak cipher; TLS 1.0 enabled; verbose stack traces. |
| **Low** | Limited impact or hard to exploit; hardening gap. | Unpinned dependency ranges; directory listing of non-sensitive static assets; missing `USER` in a build-only image. |
| **Informational** | No direct risk; good-practice recommendation or observation. | Actions not pinned to SHA; server version banner; prompt-injection text in docs. |

Scanner rules carry a default severity; the agent must re-evaluate it with context.

## 2. Context modifiers

Raise severity when:

- the endpoint is internet-facing and unauthenticated;
- the affected data is credentials, payment data, health data, or PII at scale;
- exploitation is automatable (no user interaction, low complexity);
- the issue is in shared infrastructure/CI with access to production secrets.

Lower severity (with justification) when:

- reachable only by trusted administrators or from a private network with other controls;
- input is constrained (e.g. converted to `int`, matched against an allow-list) — often this makes it a
  False Positive rather than a lower severity;
- code is test-only, example, or dead code (verify it is not shipped);
- an effective compensating control exists (WAF alone is *not* sufficient for injection).

**Secrets**: severity depends on credential type and privileges (cloud root keys > read-only API key),
whether it looks real (format, entropy, provider prefix), whether it is test/sandbox (`sk_test_`), and
exposure (public repository, history). Never assign Critical solely because something matched a pattern.

## 3. Confidence

Confidence is the strength of the **evidence**, independent of severity.

| Confidence | Meaning |
|---|---|
| High | Sink and the problematic configuration are unambiguous; for code, untrusted input is shown to reach the sink. |
| Medium | Pattern clearly present; source of data or reachability not fully established. |
| Low | Weak signal: may be test code, intentional, or depends on unseen context. |

The scanner raises confidence when request-derived data appears on the same line (name-based, intra-file
taint) and lowers it for test/example paths or when a mitigation appears elsewhere in the file.

## 4. Status

| Status | Use when | Set by |
|---|---|---|
| Confirmed | Evidence establishes the vulnerable path/configuration and no effective control exists. | agent/human only |
| Probable | Pattern present and exploitation plausible; at least one link unverified. | scanner default for strong rules; agent |
| Needs Manual Review | Impact depends on context not visible in the code (deployment, intent). | scanner for weak rules; agent |
| False Positive | Verified not exploitable; justification mandatory. | agent/human via triage |
| Not Verified | A check could not be performed (no network, tool missing, version unresolved). | scanner/agent |

The scanner never sets `Confirmed`. Any status/severity change goes through a triage file and keeps the
original values in `finding.triage`.

## 5. Remediation priority

Computed by `scr_common.remediation_priority(severity, confidence, status)`:

| Priority | Rule (first match wins) | Meaning |
|---|---|---|
| P4 | status False Positive, or severity Informational | backlog |
| P1 | severity Critical/High **and** confidence High **and** status Confirmed/Probable | fix immediately |
| P2 | Critical (any confidence), or High with Medium/High confidence, or Medium with High confidence and Confirmed/Probable | next sprint |
| P3 | remaining Critical–Low | planned hardening |

The roadmap orders items inside a priority by estimated effort (Low first). Effort is a rule-level
estimate (`effort` field); the agent should adjust it for the codebase.

## 6. CVSS v4.0 methodology

CVSS is optional and must never be guessed. Provide it only when every base metric can be justified from
evidence.

1. Determine base metrics:
   - **Exploitability**: Attack Vector (AV: N/A/L/P), Attack Complexity (AC: L/H), Attack Requirements
     (AT: N/P), Privileges Required (PR: N/L/H), User Interaction (UI: N/P/A).
   - **Vulnerable system impact**: VC, VI, VA (H/L/N).
   - **Subsequent system impact**: SC, SI, SA (H/L/N).
2. Build the vector, e.g. `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`.
3. Compute the score with the official FIRST calculator (https://www.first.org/cvss/calculator/4.0) or a
   library that implements the specification's MacroVector lookup tables. The scripts in this skill do
   **not** compute CVSS scores.
4. Record in the finding:
   ```json
   "cvss": {"version": "4.0", "vector": "CVSS:4.0/AV:N/...", "score": 9.3,
            "rationale": "AV:N public route /users; PR:N no auth decorator; VC:H full users table..."}
   ```
   If you cannot compute the score with a trusted calculator, set `"score": null` and keep the vector
   and rationale.
5. CVSS measures technical severity; the skill's `severity` may differ when business context justifies
   it — explain the difference.

## 7. Exploitability and business impact

- `exploitability`: preconditions and attacker effort ("requires an authenticated user; ids are
  sequential; no rate limiting").
- `business_impact`: consequence for the organization ("exposure of customer invoices; likely notifiable
  incident"). The scanner leaves a placeholder stating it was not assessed; fill it in for Confirmed and
  Probable High/Critical findings when context is available, otherwise leave the placeholder.

## 8. Worked examples

| Situation | Classification |
|---|---|
| f-string SQL in a public Flask route using `request.args` directly | High or Critical, confidence High, Confirmed after tracing |
| String-concatenated SQL whose only variable is `int(page)` | False Positive (justification: integer cast) |
| `hashlib.md5` for cache keys | False Positive / Informational |
| `hashlib.md5(password)` stored in the user table | High, Confirmed, CWE-916 |
| Generic high-entropy `API_KEY = "..."` in `tests/fixtures` | Low/Medium, confidence Low, Needs Manual Review (verify the key is fake) |
| `privileged: true` in `docker-compose.override.yml` used only for local dev | Low/Medium, Needs Manual Review; document the assumption |
| `pull_request_target` + checkout of PR head + secrets in later steps | Critical or High, Confirmed |
