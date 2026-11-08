# Configuration & Infrastructure Security

## Contents

1. Docker / Dockerfile
2. Docker Compose
3. Kubernetes
4. Terraform (AWS, Azure, GCP)
5. CI/CD (GitHub Actions, GitLab CI, Azure Pipelines)
6. Web servers (Nginx, Apache)
7. Application configuration and environment files
8. Reviewing context before rating

---

## 1. Dockerfile

| Check | Finding if | Rule |
|---|---|---|
| Non-root runtime user | `USER root`/`USER 0`, or no `USER` at all | `container.docker.user-root`, `container.docker.no-user` |
| Pinned base image | `FROM image` without tag or `:latest` | `container.docker.unpinned-base-image` |
| No secrets in layers | `ENV/ARG *PASSWORD*/*TOKEN*` with values; `COPY .env` | `container.docker.secret-in-env` |
| Verified downloads | `curl ... \| sh`, `ADD https://...` | `supply-chain.remote-script-pipe` |
| Minimal image | dev tools, compilers in final stage → recommend multi-stage builds | agent |

Secrets needed at build time: use BuildKit secrets (`RUN --mount=type=secret,...`).

## 2. Docker Compose

`privileged: true`, `/var/run/docker.sock` mounts (full host control), `network_mode: host`, `pid: host`,
`cap_add: [ALL|SYS_ADMIN|...]`, ports bound to `0.0.0.0` for databases/admin UIs, plaintext secrets in
`environment:`. Check whether the file is development-only (e.g. `docker-compose.override.yml`) before
rating — and say so.

## 3. Kubernetes

Pod/container `securityContext` (compare with Pod Security Standards "restricted"):
`runAsNonRoot: true`, no `runAsUser: 0`, `allowPrivilegeEscalation: false`, `privileged: false`,
`capabilities.drop: ["ALL"]`, `readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`.
Also: `hostNetwork/hostPID/hostIPC`, `hostPath` volumes, `automountServiceAccountToken` for pods that do not
call the API, RBAC (`ClusterRoleBinding` to `cluster-admin`, wildcard verbs/resources), `Secret` manifests
with real values committed, `Service type: LoadBalancer` exposure, missing NetworkPolicies, missing resource
limits (DoS).

## 4. Terraform

| Area | Insecure | Rule |
|---|---|---|
| Network | ingress `0.0.0.0/0` / `::/0` on admin or DB ports (egress is usually fine and is ignored) | `iac.network.open-to-world` |
| Storage | `acl = "public-read"`, public access blocks disabled, `allow_blob_public_access = true` | `iac.storage.public-acl` |
| Databases | `publicly_accessible = true`, `storage_encrypted = false` | `iac.storage.public-acl`, `iac.encryption-disabled` |
| IAM | `"Action": "*"`, `"Principal": "*"`, `Owner` role assignment | `iac.iam.wildcard` |
| TLS | `min_tls_version` < 1.2, `https_only = false` | `iac.tls.min-version`, `iac.encryption-disabled` |
| State | state in local files committed (`*.tfstate` contains secrets) | agent: check for `*.tfstate` |

Recommend policy-as-code in CI (Checkov, Trivy config, tfsec, OPA/Conftest) and review `terraform plan`.

## 5. CI/CD

### GitHub Actions
- `permissions:` at workflow or job level, minimal (`contents: read`); never `write-all`.
- Untrusted event data (`github.event.issue.title`, `...pull_request.title/body`, `github.head_ref`,
  comment bodies) **must not** be interpolated inside `run:` — pass via `env:` and quote `"$VAR"`.
- `pull_request_target` and `workflow_run` run with secrets: never check out and execute PR code in them.
- Pin third-party actions to a full commit SHA (tags are mutable).
- Do not echo secrets; use OIDC (`id-token: write`) for cloud access instead of long-lived keys.
- Self-hosted runners must not run untrusted PRs.

### GitLab CI / Azure Pipelines
Protected variables only on protected branches; masked variables; no `echo $TOKEN`; pinned images in
`image:`; avoid `curl | sh`; restrict pipelines for forks; limit service connection scopes (Azure).

## 6. Web servers

Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`, modern `ssl_ciphers`, `server_tokens off;`, `autoindex off;`,
security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`,
`frame-ancestors`), request size limits, no `add_header Access-Control-Allow-Origin *` on authenticated APIs.
Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`, `Options -Indexes`, `ServerTokens Prod`, `ServerSignature Off`.

## 7. Application configuration

Debug flags (`DEBUG = True`, `app.run(debug=True)`, `UseDeveloperExceptionPage` outside development),
`ALLOWED_HOSTS = ['*']`, CORS wildcards with credentials, Spring Actuator `exposure.include=*`, committed
`.env` files, default credentials in `appsettings.json`/`application.properties`, verbose error settings.
Environment templates (`.env.example`) should contain placeholders only.

## 8. Context before rating

Configuration findings depend on deployment. Before Confirming: is the file used in production (CI deploys
it, Helm values reference it), or only locally/tests? Are there overrides (Kustomize overlays, Helm values,
Terraform modules/variables) that change the value? Document assumptions in `exploitability`.
