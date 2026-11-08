# OWASP, CWE and ASVS Mapping

Findings use **OWASP Top 10:2021** identifiers in `owasp_category` (format `A03:2021-Injection`) and
**OWASP API Security Top 10:2023** in `owasp_api_category` when the finding concerns an API. A newer
OWASP Top 10 edition may be available; if the user asks for it, map using the official list at
https://owasp.org/Top10/ and do not invent category names.

## Contents

1. OWASP Top 10:2021 ↔ common CWEs ↔ scanner rules
2. OWASP API Security Top 10:2023
3. OWASP ASVS chapter mapping (Compliance Mapping mode)
4. Rules for compliance statements

---

## 1. OWASP Top 10:2021

| Category | Common CWEs | Scanner rule families |
|---|---|---|
| A01:2021-Broken Access Control | 22, 284, 285, 352, 601, 639, 862, 863, 269 | `path-traversal.*`, `csrf.*`, `open-redirect.*`, `iac.iam.wildcard`; IDOR = agent review |
| A02:2021-Cryptographic Failures | 295, 311, 319, 326, 327, 328, 338, 916 | `crypto.*`, `tls.*`, `iac.tls.*`, `webserver.legacy-tls`, `iac.encryption-disabled` |
| A03:2021-Injection | 78, 79, 89, 94, 95, 943, 1336 | `injection.*`, `xss.*`, `cicd.gha.script-injection` |
| A04:2021-Insecure Design | 209, 377, 434, 1427 | `file-upload.*`, `errors.*`, `race.*`; business logic = agent review |
| A05:2021-Security Misconfiguration | 16, 200, 250, 284, 489, 538, 548, 611, 614, 732, 942 | `config.*`, `container.*`, `webserver.*`, `xxe.*`, `iac.*` |
| A06:2021-Vulnerable and Outdated Components | 1104, 1357, 1395 | `dependencies.*` |
| A07:2021-Identification and Authentication Failures | 256, 307, 321, 347, 613, 798 | `auth.*`, `secrets.*` |
| A08:2021-Software and Data Integrity Failures | 494, 502, 829, 915, 1321 | `deserialization.*`, `supply-chain.*`, `mass-assignment.*`, `prototype-pollution.*`, `cicd.gha.*` |
| A09:2021-Security Logging and Monitoring Failures | 532, 778 | `logging.*`, `cicd.secret-echo` |
| A10:2021-Server-Side Request Forgery | 918 | `ssrf.*` |

CWE definitions: `https://cwe.mitre.org/data/definitions/<number>.html`.

## 2. OWASP API Security Top 10:2023

| Category | What to check | Detection |
|---|---|---|
| API1:2023-Broken Object Level Authorization | Object ids in path/query/body accessed without ownership/tenant checks | agent review |
| API2:2023-Broken Authentication | Token validation, credential stuffing protection, password reset | `auth.jwt.*` + agent |
| API3:2023-Broken Object Property Level Authorization | Mass assignment; over-exposed response fields | `mass-assignment.*` + agent (serializers/DTOs) |
| API4:2023-Unrestricted Resource Consumption | Pagination limits, upload size, rate limiting, GraphQL depth/complexity | agent |
| API5:2023-Broken Function Level Authorization | Admin/privileged routes reachable by normal users | agent |
| API6:2023-Unrestricted Access to Sensitive Business Flows | Automation abuse of purchase/sign-up/booking flows | agent |
| API7:2023-Server Side Request Forgery | User-supplied URLs fetched server-side | `ssrf.*` |
| API8:2023-Security Misconfiguration | CORS, verbose errors, debug, TLS, missing security headers | `config.*`, `errors.*` |
| API9:2023-Improper Inventory Management | Old/undocumented API versions, debug endpoints exposed | agent (route inventory) |
| API10:2023-Unsafe Consumption of APIs | Trusting third-party API responses without validation, TLS disabled | `tls.*` + agent |

## 3. OWASP ASVS mapping

Use ASVS chapter-level mapping. The table uses the chapter structure of ASVS 4.0.3. ASVS 5.0 reorganized
chapters; if the user targets 5.0, map against the official 5.0 document and cite requirement ids only
after checking them there.

| ASVS 4.0.3 chapter | Related finding categories |
|---|---|
| V1 Architecture, Design and Threat Modeling | threat model gaps, missing trust boundaries |
| V2 Authentication | weak password storage, brute-force protection, credential handling, hardcoded credentials |
| V3 Session Management | cookie flags, session fixation, token expiry |
| V4 Access Control | IDOR, missing authorization, CSRF, privilege escalation |
| V5 Validation, Sanitization and Encoding | injection, XSS, SSRF, deserialization, mass assignment |
| V6 Stored Cryptography | weak hashes/ciphers, insecure randomness, key management |
| V7 Error Handling and Logging | stack traces, sensitive data in logs |
| V8 Data Protection | sensitive data exposure, caching of sensitive data |
| V9 Communication | TLS configuration, certificate validation |
| V10 Malicious Code | dependency integrity, remote scripts, backdoors |
| V11 Business Logic | logic flaws, race conditions |
| V12 Files and Resources | path traversal, uploads, XXE |
| V13 API and Web Service | REST/GraphQL specific issues, CORS |
| V14 Configuration | debug mode, container/IaC hardening, dependency management, HTTP headers |

## 4. Rules for compliance statements

- A static review **cannot** establish compliance with ASVS, PCI DSS, ISO 27001, SOC 2, HIPAA or any other
  standard. Say: "Findings mapped to ASVS chapters V4 and V5; this is not a compliance assessment."
- Map only what you reviewed; list unreviewed chapters explicitly.
- Never claim a requirement "passes" based on absence of scanner findings.
