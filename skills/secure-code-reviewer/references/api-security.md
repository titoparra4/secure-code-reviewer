# API Security Review (REST, GraphQL, backend services)

Use with `--mode api`. Map findings to OWASP API Security Top 10:2023 (`owasp_api_category`).

## Contents

1. Build the API inventory
2. Per-endpoint checklist
3. GraphQL specifics
4. Service-to-service and webhooks
5. .NET / Java / Node / Python quick references

---

## 1. API inventory

From routes/controllers/OpenAPI files list: method, path, authentication requirement, roles, object ids
accepted, request body schema, response schema. Flag:
- endpoints without authentication that return non-public data;
- old versions (`/v1` alongside `/v2`) still routed (API9);
- debug/internal endpoints (`/debug`, `/internal`, `/actuator`, `/swagger` in production) (API8/API9).

## 2. Per-endpoint checklist

| # | Check | API Top 10 |
|---|---|---|
| 1 | Object ids are scoped to the caller (ownership/tenant) | API1 |
| 2 | Authentication is enforced and token validation is complete | API2 |
| 3 | Request bodies bind to explicit DTOs; responses do not over-expose fields (passwords, internal flags) | API3 |
| 4 | Pagination limits, max page size, upload size, timeouts, rate limits | API4 |
| 5 | Privileged operations check roles/permissions server-side | API5 |
| 6 | Business-critical flows have anti-automation (rate limit, CAPTCHA, idempotency keys) | API6 |
| 7 | URLs from clients are not fetched without allow-listing | API7 |
| 8 | CORS, error verbosity, TLS, security headers, HTTP methods | API8 |
| 9 | Inventory/versions documented and old versions retired | API9 |
| 10 | Third-party API responses validated; TLS verification on outbound calls | API10 |

Also: input validation (types, ranges, formats), injection sinks reached from parameters, content-type
enforcement, JSON parser limits, mass assignment, and logging of security events without sensitive data.

## 3. GraphQL

- Authorization per resolver/field, not just per query entry point (nested object leaks).
- Depth/complexity limits and query cost analysis; disable or restrict introspection in production when
  appropriate; batching/alias abuse limits (brute force via aliases).
- Persisted queries for public clients when feasible.
- Error messages do not expose stack traces or internal schema details beyond what is intended.

## 4. Service-to-service and webhooks

- mTLS or signed tokens between services; do not trust network location alone.
- Webhooks: verify HMAC signatures with constant-time comparison and timestamp tolerance (replay
  protection); secrets from configuration.
- Outbound calls: timeouts, TLS verification, response size limits, schema validation.

## 5. Framework quick references

| Stack | Authorization hooks | Binding/DTO | Typical pitfalls |
|---|---|---|---|
| ASP.NET Core | `[Authorize(Policy=...)]`, resource-based `IAuthorizationService` | DTO records, `[Bind]`, avoid binding EF entities | `[AllowAnonymous]` on controller, `TokenValidationParameters` flags false, `AllowAnyOrigin` |
| Spring | `@PreAuthorize`, `SecurityFilterChain` | DTOs, `@JsonIgnore` | `permitAll()` overly broad, `csrf().disable()` with cookie auth, actuator exposure |
| Express/Nest | middleware/guards | `zod`/`class-validator` | `Object.assign(entity, req.body)`, missing `await` on auth checks, `cors()` default |
| Django REST | `permission_classes`, `get_queryset` | serializers with explicit `fields` | `fields = "__all__"`, `AllowAny` default |
| FastAPI | `Depends()` with scopes | Pydantic models (`response_model`) | returning ORM objects without `response_model` |
