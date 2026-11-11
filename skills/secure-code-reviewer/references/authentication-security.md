# Authentication & Authorization Review

**Authentication** answers "who is this?"; **authorization** answers "may this identity do this to this
object?". Report them separately: a perfectly verified JWT does not prevent IDOR.

## Contents

1. Review procedure
2. Password storage and login
3. Sessions and cookies
4. JWT
5. OAuth 2.0 / OpenID Connect
6. Authorization: RBAC, ABAC, object-level checks
7. Framework hot spots

---

## 1. Review procedure

1. Locate the authentication mechanism (inventory `auth_mechanisms`, middleware, login routes).
2. Enumerate routes and mark which require authentication and which roles (decorators, middleware,
   attributes like `[Authorize]`, `@PreAuthorize`, route groups).
3. Find routes that **should** be protected but are not (admin, export, internal, debug endpoints).
4. For every route taking an object identifier, check object-level authorization (section 6).
5. Review token/session lifecycle: issuance, validation, expiry, refresh, revocation, logout.
6. Review credential flows: registration, login, password reset, MFA enrollment/verification.

## 2. Password storage and login

| Check | Secure | Insecure (finding) |
|---|---|---|
| Hashing | Argon2id, scrypt, bcrypt (cost ≥ 10), PBKDF2 with high iterations | MD5/SHA-1/SHA-256 unsalted or single-iteration (CWE-916), plaintext (CWE-256), reversible encryption |
| Comparison | library `verify()` (constant time) | `==` on hashes or plaintext |
| Brute force | rate limiting / lockout / CAPTCHA per account and IP (CWE-307) | unlimited attempts |
| Enumeration | identical responses/timing for unknown user vs wrong password | "user not found" vs "wrong password" |
| Reset tokens | CSPRNG, single-use, short expiry, stored hashed | `random`, `Math.random`, long-lived, reusable (CWE-640/338) |
| MFA | enforced for admins; verification bound to session; rate-limited | bypassable step, codes not rate-limited |

## 3. Sessions and cookies

- Cookies: `Secure`, `HttpOnly`, `SameSite=Lax|Strict` (CWE-614, CWE-1004).
- Regenerate session id on login and privilege change (session fixation, CWE-384).
- Server-side invalidation on logout; idle and absolute timeouts (CWE-613).
- Session secrets come from configuration, not code (CWE-798); `SECRET_KEY` hardcoded is a finding.
- CSRF protection for cookie-authenticated state-changing requests (CWE-352).

## 4. JWT

| Check | Insecure pattern | CWE |
|---|---|---|
| Signature verified | `jwt.decode(..., options={"verify_signature": False})`, `jwt.decode` (jsonwebtoken) used for auth, `parseUnsecuredClaims`, `RequireSignedTokens = false` | 347 |
| Algorithm pinned | no `algorithms=[...]`, `none` accepted, HS/RS confusion (public key used as HMAC secret) | 347 / 327 |
| Expiry | `verify_exp: False`, `ignoreExpiration: true`, `ValidateLifetime = false`, tokens without `exp` | 613 |
| Issuer/audience | `ValidateIssuer/ValidateAudience = false`, no `iss`/`aud` checks in multi-tenant/multi-service setups | 287 |
| Key strength | short HMAC secrets, hardcoded keys | 326 / 798 |
| Storage | tokens in `localStorage` + XSS present (escalates XSS impact) | 922 |
| Revocation | no way to revoke long-lived refresh tokens | 613 |

Secure Python example:
```python
claims = jwt.decode(token, public_key, algorithms=["RS256"], audience="orders-api", issuer=ISSUER)
```
Secure Node example:
```js
const claims = jwt.verify(token, publicKey, { algorithms: ["RS256"], audience: "orders-api", issuer: ISSUER });
```
Tests: token signed with another key → 401; `alg: none` → 401; expired → 401; wrong `aud` → 401; valid → 200.

## 5. OAuth 2.0 / OpenID Connect

- Authorization Code flow with **PKCE** for public clients; no implicit flow for new code.
- `state` parameter generated, bound to the session and verified (CSRF on login).
- `redirect_uri` exact-match allow-list; no open redirects on the callback path (CWE-601).
- ID token validation: signature, `iss`, `aud`, `exp`, `nonce` (OIDC).
- Client secrets only in confidential clients, loaded from a secret store.
- Scopes minimal; access tokens not logged; refresh tokens rotated.

## 6. Authorization

### Object-level (IDOR / BOLA — CWE-639, API1:2023)
For each handler with an id parameter:
```python
# vulnerable
invoice = Invoice.query.get(invoice_id)
# secure
invoice = Invoice.query.filter_by(id=invoice_id, owner_id=current_user.id).first_or_404()
```
Also check: bulk endpoints, exports, GraphQL resolvers (per-field), file downloads, nested resources
(`/orgs/{org}/projects/{id}` must verify the project belongs to the org *and* the user belongs to the org).

### Function-level (BFLA — CWE-285, API5:2023)
Admin and privileged routes must enforce roles server-side; hiding UI elements is not a control.
Look for inconsistent decorators between similar routes and HTTP-method gaps (GET protected, DELETE not).

### RBAC / ABAC
- Central policy (middleware, policy classes) instead of scattered `if user.role == "admin"`.
- Deny by default; explicit allow.
- ABAC attributes (tenant, owner, department) must come from trusted server-side state, not the request.
- Privilege escalation: users must not be able to change their own role/tenant (mass assignment).

### Tests
For each confirmed authorization finding, write a two-user test: user A cannot read/modify user B's
resource (expect 403/404), user A can still access their own (expect 200).

## 7. Framework hot spots

| Framework | Where to look |
|---|---|
| Flask | `@login_required` coverage, `before_request` hooks, `SECRET_KEY`, `flask_jwt_extended` config |
| Django | `LoginRequiredMixin`/`@login_required`, `permission_classes` (DRF), `get_queryset` scoping, `SESSION_COOKIE_*`, `CSRF_*` |
| FastAPI | `Depends(get_current_user)` on routers, scope checks, OAuth2PasswordBearer config |
| Express | middleware order (`app.use(auth)` before routes), passport strategies, `express-session` cookie options |
| Spring | `SecurityFilterChain`, `@PreAuthorize`, `csrf().disable()`, method security enabled |
| ASP.NET Core | `[Authorize]`/`[AllowAnonymous]`, `AddAuthentication().AddJwtBearer(TokenValidationParameters)`, policies, `UseAuthorization()` order |
| Laravel | `auth` middleware, policies/gates, `$fillable`/`$guarded` |
| Rails | `before_action :authenticate_user!`, Pundit/CanCan policies, strong parameters |
