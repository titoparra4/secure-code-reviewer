# Dependency Security Analysis

## Contents

1. Supported manifests and lockfiles
2. What the offline analysis does
3. Advisory verification (OSV) — opt-in network
4. Status semantics
5. Recommending upgrades safely
6. Alternatives and complements

---

## 1. Supported files

| Ecosystem | Manifests | Lockfiles (resolve exact versions) |
|---|---|---|
| PyPI | `requirements*.txt`, `pyproject.toml` (PEP 621 and Poetry) | `poetry.lock` |
| npm | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Maven | `pom.xml` (with `${property}` resolution), `build.gradle(.kts)` | — |
| NuGet | `*.csproj` (`PackageReference`) | `packages.lock.json` |
| Go | `go.mod` | not needed: `go.mod` versions are exact (`go.sum` holds checksums only) |
| crates.io | `Cargo.toml` | `Cargo.lock` |

Parsing is regex/JSON based and never runs package managers, build scripts or plugins. Not supported:
Gemfile/Gemfile.lock, composer, Pipfile.lock, conda, Gradle version catalogs, Maven parent/BOM resolution.
Say so in the report when these files exist.

## 2. Offline analysis

Findings produced without network:

| Rule | Severity | Meaning |
|---|---|---|
| `dependencies.untrusted-source` | Medium | git/URL/path sources bypass registry integrity guarantees |
| `dependencies.wildcard-version` | Medium | `*`, `latest`, `+`: any future (possibly malicious) version installs |
| `dependencies.not-pinned` | Low | ranges without lockfile; one finding per manifest |
| `dependencies.missing-lockfile` | Informational | npm project without a lockfile |

Every dependency gets `vulnerability_status: "Not Verified"` offline, and the report lists this as a pending
verification. **Never** state that a dependency is vulnerable or safe from memory: CVE data changes daily.
If you recognize a famous vulnerable version (e.g. a well-known RCE), you may mention it as "to verify" and
recommend running an advisory check, but do not record a CVE id, affected range or fixed version you have not
retrieved from an authoritative source during this session.

## 3. OSV verification (`--osv`)

- Requires explicit user consent: package **names, versions and ecosystems** are sent to `https://api.osv.dev`;
  no source code.
- Uses `POST /v1/querybatch` then `GET /v1/vulns/{id}` for details (summary, aliases, severity from
  `database_specific.severity` when present, fixed versions from `affected[].ranges[].events[].fixed`).
- Only dependencies with an exact version (pinned or resolved from a lockfile) are queried; others stay
  `Not Verified` with a `verification_note`.
- Network/API failures are recorded in `tool_errors`; statuses remain `Not Verified`.
- Matches become `dependencies.known-vulnerability` findings with status `Probable`: the version is affected,
  but **reachability** (whether the vulnerable function is used) was not assessed. Upgrade to `Confirmed`
  only after checking usage.

## 4. Status semantics

| Status | Meaning |
|---|---|
| Not Verified | no lookup performed or version unresolved — not evidence of safety |
| No Known Vulnerabilities | OSV returned no advisories at query time |
| Vulnerable | OSV returned at least one advisory for this exact version |

## 5. Recommending upgrades

- Prefer the smallest version that fixes all advisories (patch/minor) to limit breaking changes.
- Only cite fixed versions returned by the advisory source.
- Check transitive dependencies: the fix may require upgrading the direct parent.
- Regenerate the lockfile; run the full test suite; review changelogs for breaking changes.
- If no fix exists: assess reachability, apply mitigations (input validation, feature disablement), or
  replace the package; document the accepted risk.

## 6. Alternatives and complements

Deterministic tools that teams can run in CI (install them separately; this skill does not install them):
OSV-Scanner, `pip-audit`, `npm audit`, `dotnet list package --vulnerable`, `govulncheck` (with reachability
for Go), `cargo audit`, OWASP Dependency-Check, Trivy, GitHub Dependabot alerts.
