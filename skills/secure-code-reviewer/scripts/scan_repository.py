#!/usr/bin/env python3
"""Secure Code Reviewer - local heuristic scanner.

Walks a directory (read-only), applies heuristic security rules, detects secrets (redacted),
parses dependency manifests and emits a findings document (schemas/findings.schema.json).

What this is NOT: a complete SAST engine. Results are candidate findings for agent/human triage.
The scanner never executes code from the audited repository and never sends source code anywhere.
Network access happens only with --osv (package names/versions to api.osv.dev) or via external
tools you explicitly enable with --external.

Exit codes: 0 = scan completed (findings may exist), 2 = usage or I/O error.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dependency_parsers as deps_mod  # noqa: E402
import external_tools  # noqa: E402
import rules as R  # noqa: E402
import scr_common as C  # noqa: E402

ALL_TAGS = {"code", "auth", "api", "config", "secrets", "meta"}
MODE_TAGS: Dict[str, Set[str]] = {
    "quick": ALL_TAGS,
    "full": ALL_TAGS,
    "pr": ALL_TAGS,
    "api": {"code", "auth", "api", "secrets", "meta"},
    "secrets": {"secrets", "meta"},
    "dependencies": set(),
    "config": {"config", "secrets", "meta"},
}
MODE_SECRETS = {"quick", "full", "pr", "api", "secrets", "config"}
MODE_DEPS = {"full", "pr", "dependencies"}
QUICK_MIN_SEVERITY = "High"  # quick mode keeps only High+ code/auth rules (all secrets/config rules)

COVERAGE_CATEGORIES: List[Tuple[str, Set[str], str]] = [
    ("Injection (SQL/NoSQL/Command/Code/SSTI)", {"code"}, "heuristic line rules + intra-file taint"),
    ("Cross-Site Scripting (XSS)", {"code"}, "heuristic sinks"),
    ("Cross-Site Request Forgery (CSRF)", {"code", "auth"}, "disabled-protection markers only"),
    ("Server-Side Request Forgery (SSRF) / Open Redirect", {"code"}, "sinks reached by request input"),
    ("Path Traversal / File Upload", {"code"}, "sinks reached by request input"),
    ("Insecure Deserialization / XXE", {"code"}, "unsafe API usage"),
    ("Mass Assignment / Prototype Pollution", {"code"}, "request-body binding patterns"),
    ("Cryptography (hashing, ciphers, randomness, TLS)", {"auth"}, "unsafe API usage"),
    ("Authentication & JWT validation", {"auth"}, "disabled verification markers"),
    ("Session management (cookies)", {"auth"}, "insecure cookie flags"),
    ("Error handling & sensitive logging", {"code"}, "heuristic patterns"),
    ("Secrets exposure", {"secrets"}, "vendor patterns + contextual generic assignments"),
    ("Containers / Kubernetes / Compose", {"config"}, "configuration rules"),
    ("Terraform / Cloud IaC", {"config"}, "configuration rules"),
    ("CI/CD pipelines", {"config"}, "configuration rules"),
    ("Web server TLS & configuration", {"config"}, "configuration rules"),
]
MANUAL_ONLY = [
    ("Broken Access Control / IDOR / authorization policies (RBAC/ABAC)",
     "requires reasoning about ownership and policy; review routes and data access manually or with the agent"),
    ("Business logic flaws", "requires domain understanding; not detectable by pattern rules"),
    ("Race conditions with security impact",
     "only insecure temp-file APIs are flagged; check-then-act races require manual review"),
    ("Brute-force protection / MFA / password policy", "requires reviewing authentication flows end to end"),
]

FRAMEWORK_MARKERS = {
    "Flask": r"\bfrom flask import|\bflask\b[=<>~ ]", "Django": r"\bdjango\b", "FastAPI": r"\bfastapi\b",
    "Express": r"[\"']express[\"']", "NestJS": r"@nestjs/", "Next.js": r"[\"']next[\"']\s*:", "React": r"[\"']react[\"']\s*:",
    "Vue": r"[\"']vue[\"']\s*:", "Angular": r"@angular/core", "Spring": r"org\.springframework",
    "ASP.NET Core": r"Microsoft\.AspNetCore", "Laravel": r"laravel/framework", "Rails": r"\brails\b",
    "Gin": r"github\.com/gin-gonic/gin", "Koa": r"[\"']koa[\"']",
}
AUTH_MARKERS = {
    "JWT": r"(?i)\bjwt\b|jsonwebtoken|System\.IdentityModel\.Tokens", "OAuth2/OIDC": r"(?i)oauth|openid|oidc",
    "Session cookies": r"(?i)SESSION_COOKIE|express-session|flask_login|HttpContext\.Session",
    "Passport.js": r"[\"']passport", "Spring Security": r"spring-boot-starter-security|EnableWebSecurity",
    "ASP.NET Identity/Auth": r"AddAuthentication|AddIdentity", "Django auth": r"django\.contrib\.auth",
}
ENTRYPOINT_NAMES = {"app.py", "main.py", "manage.py", "wsgi.py", "asgi.py", "server.js", "server.ts", "index.js",
                    "app.js", "app.ts", "main.ts", "main.go", "program.cs", "startup.cs", "index.php"}
ROUTE_MARKERS = re.compile(r"@\w+(\.\w+)*\.(route|get|post|put|delete|patch)\(|\b(app|router)\.(get|post|put|delete|patch|all)\(|"
                           r"@(Get|Post|Put|Delete|Patch|Request)Mapping|\[(HttpGet|HttpPost|HttpPut|HttpDelete|Route)\b|Map(Get|Post|Put|Delete)\(")
LANG_BY_EXT = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
               ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".php": "PHP",
               ".go": "Go", ".rb": "Ruby", ".rs": "Rust", ".tf": "Terraform", ".yml": "YAML", ".yaml": "YAML",
               ".sh": "Shell", ".html": "HTML", ".vue": "Vue", ".scala": "Scala", ".swift": "Swift"}


# --------------------------------------------------------------------------- helpers

def lower_conf(conf: str) -> str:
    return C.CONFIDENCES[min(C.CONFIDENCE_RANK[conf] + 1, 2)]


def raise_conf(conf: str) -> str:
    return C.CONFIDENCES[max(C.CONFIDENCE_RANK[conf] - 1, 0)]


def make_finding(*, rule_id: str, title: str, category: str, profile: str, cwe: str, owasp: str, severity: str,
                 confidence: str, status: str, rel: str, start: int, end: int, snippet: str, source: str,
                 description: Optional[str] = None, notes: Optional[List[str]] = None,
                 owasp_api: Optional[str] = None, occurrence: int = 0, extra: Optional[Dict[str, Any]] = None
                 ) -> Dict[str, Any]:
    prof = R.P.get(profile, R.P["secret"] if source == "gitleaks" else {})
    sanitized = C.sanitize_text(snippet)
    f: Dict[str, Any] = {
        "id": "SCR-0000",
        "fingerprint": C.fingerprint(rule_id, rel, sanitized, occurrence),
        "rule_id": rule_id,
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "cwe": cwe,
        "owasp_category": owasp,
        "location": {"file": rel, "start_line": start, "end_line": max(end, start)},
        "evidence": {
            "description": C.sanitize_text(description or prof.get("description", title), 600),
            "sanitized_code": sanitized,
        },
        "impact": prof.get("impact", "Impact depends on context; review required."),
        "exploitability": prof.get("conditions", "Not assessed; requires manual review."),
        "business_impact": "Not assessed by the scanner; evaluate against the affected asset and data classification.",
        "remediation": {
            "recommendation": prof.get("recommendation", "Review and remediate according to the referenced CWE."),
            "fixed_code_example": prof.get("fixed_example", ""),
            "security_test": prof.get("security_test", ""),
            "regression_test": prof.get("regression_test", ""),
            "verification": prof.get("verification", "Re-run the scan and relevant tests after the fix."),
        },
        "effort": prof.get("effort", "Medium"),
        "source": source,
        "verification": {"method": "heuristic" if source == "scanner" else "external_tool", "tool": source,
                         "reproduced": False, "notes": notes or []},
        "cvss": None,
        "references": [f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
    }
    if owasp_api:
        f["owasp_api_category"] = owasp_api
    if extra:
        f.update(extra)
    f["remediation_priority"] = C.remediation_priority(severity, confidence, status)
    return f


class Scanner:
    def __init__(self, root: Path, mode: str, max_file_bytes: int, max_files: int, excludes: List[str]):
        self.root = root
        self.mode = mode
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.excludes = excludes
        self.tags = MODE_TAGS[mode]
        self.findings: List[Dict[str, Any]] = []
        self.files_scanned = 0
        self.skipped: Dict[str, int] = {}
        self.manifests: List[Tuple[str, str]] = []
        self.languages: Dict[str, int] = {}
        self.frameworks: Set[str] = set()
        self.auth: Set[str] = set()
        self.entrypoints: List[str] = []
        self.config_files: List[str] = []
        self.route_count = 0
        self._occ: Dict[Tuple[str, str, str], int] = {}
        self.rules = [r for r in R.RULES if r.tags & self.tags and
                      not (mode == "quick" and r.tags & {"code", "auth"} and not r.tags & {"config", "secrets"}
                           and C.SEVERITY_RANK[r.severity] > C.SEVERITY_RANK[QUICK_MIN_SEVERITY])]

    # ---- discovery
    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def excluded(self, rel: str) -> bool:
        from fnmatch import fnmatch

        return any(fnmatch(rel, pat) or fnmatch(PurePosixPath(rel).name, pat) for pat in self.excludes)

    def iter_files(self, only: Optional[List[str]] = None):
        if only is not None:
            for rel in sorted(set(only)):
                p = (self.root / rel)
                if not C.is_within(self.root, p):
                    self.skip("outside_target")
                    continue
                yield p
            return
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in C.SKIP_DIRS
                                 and not os.path.islink(os.path.join(dirpath, d)))
            for name in sorted(filenames):
                yield Path(dirpath) / name

    def run(self, only: Optional[List[str]] = None) -> None:
        for path in self.iter_files(only):
            rel = path.relative_to(self.root).as_posix() if C.is_within(self.root, path) else path.name
            if self.files_scanned >= self.max_files:
                self.skip("max_files_reached")
                continue
            if path.is_symlink():
                self.skip("symlink")
                continue
            if not path.is_file():
                self.skip("not_a_regular_file")
                continue
            if self.excluded(rel):
                self.skip("excluded_by_pattern")
                continue
            lname = path.name.lower()
            if any(lname.endswith(s) for s in C.SKIP_SUFFIXES):
                self.skip("binary_or_media_extension")
                continue
            try:
                size = path.stat().st_size
                if size > self.max_file_bytes:
                    self.skip("too_large")
                    continue
                raw = path.read_bytes()
            except OSError:
                self.skip("unreadable")
                continue
            if b"\x00" in raw[:8192]:
                self.skip("binary_content")
                continue
            text = raw.decode("utf-8", errors="replace")
            self.files_scanned += 1
            self.scan_file(rel, text)

    # ---- per file
    def inventory(self, rel: str, text: str) -> None:
        suffix = PurePosixPath(rel).suffix.lower()
        if R.is_dockerfile(rel):
            self.languages["Dockerfile"] = self.languages.get("Dockerfile", 0) + 1
        elif suffix in LANG_BY_EXT:
            lang = LANG_BY_EXT[suffix]
            self.languages[lang] = self.languages.get(lang, 0) + 1
        name = PurePosixPath(rel).name.lower()
        if name in ENTRYPOINT_NAMES or re.search(r"Application\.(java|kt)$", rel):
            self.entrypoints.append(rel)
        if (R.is_dockerfile(rel) or R.is_terraform(rel) or R.is_ci_file(rel) or R.is_web_server_conf(rel)
                or R.is_app_config(rel) or name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
                or (R.is_yaml(rel) and re.search(r"(?m)^kind:\s*\w+", text))):
            self.config_files.append(rel)
        if suffix in R.CODE or deps_mod.is_manifest(rel):
            sample = text[:200_000]
            for fw, pat in FRAMEWORK_MARKERS.items():
                if re.search(pat, sample):
                    self.frameworks.add(fw)
            for mech, pat in AUTH_MARKERS.items():
                if re.search(pat, sample):
                    self.auth.add(mech)
            self.route_count += len(ROUTE_MARKERS.findall(sample))

    def add(self, finding: Dict[str, Any]) -> None:
        self.findings.append(finding)

    def occurrence(self, rule_id: str, rel: str, snippet: str) -> int:
        key = (rule_id, rel, C.normalize_for_fingerprint(snippet))
        n = self._occ.get(key, 0)
        self._occ[key] = n + 1
        return n

    def scan_file(self, rel: str, text: str) -> None:
        self.inventory(rel, text)
        if deps_mod.is_manifest(rel):
            self.manifests.append((rel, text))
        lines = text.splitlines()
        is_test = C.is_test_path(rel)
        applicable = [r for r in self.rules if r.applies(rel)]
        is_code = PurePosixPath(rel).suffix.lower() in R.CODE
        tainted = R.compute_tainted(lines) if (is_code and applicable) else set()
        for rule in applicable:
            if rule.file_check:
                hit = rule.file_check(rel, lines)
                if hit:
                    self._emit_rule(rule, rel, hit[0], hit[1], is_test, {}, [])
                continue
            for idx, line in enumerate(lines):
                if len(line) > 4000:
                    continue  # minified/generated content
                if rule.skip_comments and R.COMMENT_RE.match(line):
                    continue
                ctx = R.LineCtx(rel, lines, idx, text, tainted)
                matched = rule.matcher(line, ctx) if rule.matcher else bool(rule.pattern and rule.pattern.search(line))
                if not matched or (rule.exclude and rule.exclude.search(line)):
                    continue
                has_input = ctx.has_input(line) if (rule.needs_input or rule.input_boost) else False
                if rule.needs_input and not has_input:
                    continue
                overrides = rule.adjust(line, ctx) if rule.adjust else None
                overrides = dict(overrides or {})
                if overrides.pop("suppress", False):
                    continue
                notes: List[str] = []
                if "note" in overrides:
                    notes.append(overrides.pop("note"))
                if rule.input_boost and has_input and "confidence" not in overrides:
                    overrides["confidence"] = raise_conf(rule.confidence)
                    notes.append("request-derived data appears to reach this line (name-based, intra-file)")
                if rule.needs_input:
                    notes.append("request-derived data appears to reach this line (name-based, intra-file)")
                if rule.mitigated_if and rule.mitigated_if.search(text):
                    overrides["confidence"] = lower_conf(overrides.get("confidence", rule.confidence))
                    notes.append("a possible mitigation was found elsewhere in the file")
                self._emit_rule(rule, rel, idx + 1, line, is_test, overrides, notes)
        if "secrets" in self.tags and self.mode in MODE_SECRETS:
            self.scan_secrets(rel, lines, is_test)

    def _emit_rule(self, rule: "R.Rule", rel: str, line_no: int, line: str, is_test: bool,
                   overrides: Dict[str, Any], notes: List[str]) -> None:
        confidence = overrides.get("confidence", rule.confidence)
        if is_test:
            confidence = lower_conf(confidence)
            notes = notes + ["located in a test/example/fixture path"]
        self.add(make_finding(
            rule_id=rule.id, title=overrides.get("title", rule.title), category=rule.category, profile=rule.profile,
            cwe=overrides.get("cwe", rule.cwe), owasp=rule.owasp, severity=overrides.get("severity", rule.severity),
            confidence=confidence, status=overrides.get("status", rule.status), rel=rel, start=line_no, end=line_no,
            snippet=line, source="scanner", notes=notes, owasp_api=rule.owasp_api,
            occurrence=self.occurrence(rule.id, rel, line)))

    # ---- secrets
    def scan_secrets(self, rel: str, lines: List[str], is_test: bool) -> None:
        for idx, line in enumerate(lines):
            if len(line) > 20000:
                continue
            spans: List[Tuple[int, int]] = []
            for kind, pattern, group, _visible in C.SECRET_PATTERNS:
                for m in pattern.finditer(line):
                    value = m.group(group) or ""
                    vs, ve = m.span(group)
                    if any(s <= vs < e or s < ve <= e for s, e in spans):
                        continue
                    if not self._secret_is_candidate(kind, m, value):
                        continue
                    spans.append((vs, ve))
                    meta = R.SECRET_RULE_META[kind]
                    confidence = meta["confidence"]
                    notes = ["value redacted; never stored in the report"]
                    if is_test or "test" in value.lower() or "fake" in value.lower():
                        confidence = lower_conf(confidence)
                        notes.append("located in a test/example path or value suggests test data")
                    rule_id = f"secrets.{kind}"
                    self.add(make_finding(
                        rule_id=rule_id, title=meta["title"], category="Secrets Exposure", profile="secret",
                        cwe="CWE-321" if kind == "private-key" else "CWE-798",
                        owasp="A07:2021-Identification and Authentication Failures", severity=meta["severity"],
                        confidence=confidence, status="Probable" if confidence != "Low" else "Needs Manual Review",
                        rel=rel, start=idx + 1, end=idx + 1, snippet=line, source="scanner",
                        description=f"A value matching the '{kind}' pattern was found. The value is redacted. "
                                    "If it is real: revoke/rotate it and review provider logs for misuse.",
                        notes=notes, occurrence=self.occurrence(rule_id, rel, line)))

    @staticmethod
    def _secret_is_candidate(kind: str, m: "re.Match[str]", value: str) -> bool:
        if kind == "private-key":
            return True
        if C.is_placeholder(value):
            return False
        if kind == "generic-secret-assignment":
            name = m.group(1)
            if C.GENERIC_NAME_EXCLUDE.search(name):
                return False
            if re.fullmatch(r"[A-Za-z_][\w.]*\(.*|[A-Za-z_]+\.[A-Za-z_.]+|https?://[^:@]*", value):
                return False  # references / calls / urls without credentials
            if C.PASSWORDISH.search(name):
                return len(value) >= 6 and value.lower() not in {"password", "passwd", "secret", "required", "optional"}
            return len(value) >= 12 and C.shannon_entropy(value) >= 3.0
        if kind in ("connection-string-password", "dotnet-connection-string-password"):
            return value.lower() not in {"password", "pass", "pwd", "secret", "user", "username"}
        return True

    # ---- dependencies
    def scan_dependencies(self, use_osv: bool, timeout: float) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]], List[str]]:
        dependencies, errors, lock_dirs = deps_mod.collect_dependencies(self.manifests)
        pending: List[str] = []
        if use_osv:
            errors.extend(deps_mod.query_osv(dependencies, timeout=timeout))
        if any(d["vulnerability_status"] == "Not Verified" for d in dependencies):
            pending.append("Known-vulnerability status of dependencies is 'Not Verified' "
                           + ("for unresolved versions or failed lookups" if use_osv else
                              "(offline run). Re-run with --osv, or use OSV-Scanner / GitHub Dependabot / Trivy."))
        by_manifest: Dict[str, List[Dict[str, Any]]] = {}
        for d in dependencies:
            by_manifest.setdefault(d["manifest"], []).append(d)
            if d["source"] != "registry":
                self.add(make_finding(
                    rule_id="dependencies.untrusted-source", title=f"Dependency installed from VCS/URL: {d['name']}",
                    category="Dependency Security", profile="remote-script", cwe="CWE-829",
                    owasp="A08:2021-Software and Data Integrity Failures", severity="Medium", confidence="High",
                    status="Probable", rel=d["manifest"], start=d["line"], end=d["line"], snippet=f"{d['name']} {d['spec']}",
                    source="scanner", description="Dependency resolved from a git/URL/path source bypasses registry "
                    "integrity controls and may change without a version bump.",
                    extra={"remediation": {
                        "recommendation": "Prefer a released registry version pinned with a lockfile/hash; if a VCS source is required, pin to a full commit SHA.",
                        "fixed_code_example": "", "security_test": "", "regression_test": "Rebuild and run the test suite.",
                        "verification": "Confirm the lockfile resolves to an immutable reference."}}))
            elif d["spec"].strip() in ("*", "latest", "x", "+", "latest.release", "latest.integration") or d["spec"].strip().endswith(".*") and d["ecosystem"] == "NuGet":
                self.add(make_finding(
                    rule_id="dependencies.wildcard-version", title=f"Wildcard/latest dependency version: {d['name']}",
                    category="Dependency Security", profile="image", cwe="CWE-1357",
                    owasp="A06:2021-Vulnerable and Outdated Components", severity="Medium", confidence="High",
                    status="Probable", rel=d["manifest"], start=d["line"], end=d["line"], snippet=f"{d['name']} {d['spec']}",
                    source="scanner", description="Any future release (including a compromised one) will be installed automatically."))
            if d["vulnerability_status"] == "Vulnerable":
                sevs = [a.get("severity") for a in d["advisories"] if a.get("severity")]
                severity = min(sevs, key=lambda s: C.SEVERITY_RANK[s]) if sevs else "Medium"
                ids = ", ".join(a["id"] for a in d["advisories"][:8])
                fixed = sorted({v for a in d["advisories"] for v in a.get("fixed_versions", [])})
                self.add(make_finding(
                    rule_id="dependencies.known-vulnerability",
                    title=f"{d['name']} {d['version']} matches published advisories", category="Vulnerable Dependency",
                    profile="image", cwe="CWE-1395", owasp="A06:2021-Vulnerable and Outdated Components",
                    severity=severity, confidence="High" if sevs else "Medium", status="Probable", rel=d["manifest"],
                    start=d["line"], end=d["line"], snippet=f"{d['name']} {d['spec'] or d['version']}", source="osv",
                    description=f"OSV reports: {ids}. Reachability of the vulnerable code was not assessed."
                                + ("" if sevs else " Advisory did not include a severity; review the advisory CVSS."),
                    extra={"remediation": {
                        "recommendation": (f"Upgrade to a fixed version ({', '.join(fixed[:5])}) " if fixed else
                                           "No fixed version was reported by OSV; evaluate mitigations or alternatives ")
                                          + "and regenerate the lockfile.",
                        "fixed_code_example": "", "security_test": "Re-run the dependency audit and confirm the advisory no longer matches.",
                        "regression_test": "Run the full test suite after upgrading.",
                        "verification": "Re-run with --osv (or OSV-Scanner) and confirm status 'No Known Vulnerabilities'."},
                        "references": [f"https://osv.dev/vulnerability/{a['id']}" for a in d["advisories"][:8]]}))
        for manifest, items in sorted(by_manifest.items()):
            loose = [d for d in items if d["source"] == "registry" and not d["pinned"]
                     and d["spec"].strip() not in ("*", "latest", "x", "+")]
            if loose:
                names = ", ".join(sorted(d["name"] for d in loose)[:10]) + (" ..." if len(loose) > 10 else "")
                self.add(make_finding(
                    rule_id="dependencies.not-pinned", title=f"{len(loose)} dependencies without an exact pinned version",
                    category="Dependency Security", profile="image", cwe="CWE-1357",
                    owasp="A06:2021-Vulnerable and Outdated Components", severity="Low", confidence="High",
                    status="Probable", rel=manifest, start=min(d["line"] for d in loose), end=max(d["line"] for d in loose),
                    snippet=names, source="scanner",
                    description="Version ranges without a lockfile make builds non-reproducible and prevent "
                                "accurate vulnerability verification."))
            directory = str(PurePosixPath(manifest).parent)
            if PurePosixPath(manifest).name == "package.json" and items and directory not in lock_dirs:
                self.add(make_finding(
                    rule_id="dependencies.missing-lockfile", title="npm project without a lockfile",
                    category="Dependency Security", profile="image", cwe="CWE-1357",
                    owasp="A06:2021-Vulnerable and Outdated Components", severity="Informational", confidence="High",
                    status="Probable", rel=manifest, start=1, end=1, snippet="package.json (no package-lock.json/yarn.lock/pnpm-lock.yaml)",
                    source="scanner", description="Without a lockfile, installed versions vary between builds."))
        public = []
        for d in dependencies:
            entry = {k: d[k] for k in ("name", "spec", "version", "ecosystem", "manifest", "line", "source", "pinned",
                                       "vulnerability_status", "advisories")}
            if "verification_note" in d:
                entry["verification_note"] = d["verification_note"]
            public.append(entry)
        return public, errors, pending


# --------------------------------------------------------------------------- CLI

SAFE_REF = re.compile(r"^[A-Za-z0-9][\w./~^@{}-]{0,200}$")


def changed_files_from_git(root: Path, base: str) -> List[str]:
    if not SAFE_REF.match(base) or ".." in base.replace("...", ""):
        raise ValueError("invalid git base reference")
    cmd = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", str(root), "diff",
           "--name-only", "--diff-filter=ACMR", "--no-ext-diff", "--no-textconv", f"{base}...HEAD", "--"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff failed: {proc.stderr.strip()[:200]}")
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def display_target(root: Path) -> str:
    try:
        return root.resolve().relative_to(Path.cwd().resolve()).as_posix() or "."
    except ValueError:
        return root.resolve().name


def build_document(args: argparse.Namespace) -> Dict[str, Any]:
    root = Path(args.target)
    if not root.exists():
        raise FileNotFoundError(f"target not found: {args.target}")
    single_file: Optional[str] = None
    if root.is_file():
        single_file = root.name
        root = root.parent
    root = root.resolve()
    only: Optional[List[str]] = None
    if single_file:
        only = [single_file]
    if args.mode == "pr":
        if args.changed_files_from:
            only = [ln.strip() for ln in Path(args.changed_files_from).read_text(encoding="utf-8").splitlines() if ln.strip()]
        elif args.git_diff:
            only = changed_files_from_git(root, args.git_diff)
        else:
            raise ValueError("--mode pr requires --changed-files-from FILE or --git-diff BASE_REF")
    scanner = Scanner(root, args.mode, args.max_file_bytes, args.max_files, args.exclude or [])
    scanner.run(only)
    tool_errors: List[Dict[str, str]] = []
    pending: List[str] = []
    dependencies: List[Dict[str, Any]] = []
    if args.mode in MODE_DEPS:
        dependencies, dep_errors, dep_pending = scanner.scan_dependencies(args.osv, args.tool_timeout)
        tool_errors.extend(dep_errors)
        pending.extend(dep_pending)
    external_status: Dict[str, str] = {}
    for tool in [t.strip() for t in (args.external or "").split(",") if t.strip()]:
        if tool not in external_tools.RUNNERS:
            tool_errors.append({"tool": tool, "message": "unknown external tool (supported: semgrep, gitleaks, trivy)"})
            continue
        if not external_tools.available(tool):
            external_status[tool] = "skipped: not installed"
            pending.append(f"{tool} was requested but is not installed; its checks did not run.")
            continue
        runner = external_tools.RUNNERS[tool]
        raw, err = runner(root, args.semgrep_config, args.tool_timeout) if tool == "semgrep" else runner(root, args.tool_timeout)
        if err:
            tool_errors.append({"tool": tool, "message": err})
            external_status[tool] = "error"
            continue
        external_status[tool] = f"ran: {len(raw)} results"
        for r in raw:
            if only is not None and r["file"] not in only:
                continue
            scanner.add(make_finding(
                rule_id=r["rule_id"], title=r["title"], category=r["category"], profile=r.get("profile", ""),
                cwe=r["cwe"], owasp=r["owasp_category"], severity=r["severity"], confidence=r["confidence"],
                status="Probable", rel=r["file"] or "unknown", start=max(1, r["start_line"]),
                end=max(1, r["end_line"]), snippet=r.get("snippet", ""), source=r["source"],
                description=r.get("description") or r["title"],
                occurrence=scanner.occurrence(r["rule_id"], r["file"], r.get("snippet", "") + str(r["start_line"]))))
    findings = scanner.findings
    C.assign_ids(findings)
    findings.sort(key=lambda f: (C.finding_sort_key(f), f["id"]))

    enabled = scanner.tags
    coverage = []
    for name, tags, method in COVERAGE_CATEGORIES:
        on = bool(tags & enabled)
        coverage.append({"category": name, "status": "partial" if on else "not_reviewed",
                         "method": "heuristic" if on else "none",
                         "notes": method + (" (quick mode: High/Critical rules only)" if on and args.mode == "quick" and tags & {"code", "auth"} else "")
                         if on else f"not included in mode '{args.mode}'"})
    coverage.append({"category": "Dependencies (manifests & lockfiles)",
                     "status": "partial" if args.mode in MODE_DEPS else "not_reviewed",
                     "method": ("advisory_database" if args.osv else "inventory") if args.mode in MODE_DEPS else "none",
                     "notes": ("OSV lookup enabled; reachability not assessed" if args.osv else
                               "offline inventory; vulnerability status Not Verified") if args.mode in MODE_DEPS
                     else f"not included in mode '{args.mode}'"})
    for name, note in MANUAL_ONLY:
        coverage.append({"category": name, "status": "not_reviewed", "method": "none", "notes": note})
    for tool, status in external_status.items():
        coverage.append({"category": f"External tool: {tool}", "status": "partial" if status.startswith("ran") else "not_reviewed",
                         "method": "external_tool", "notes": status})
    pending.append("Heuristic findings are candidates: each needs triage (Confirmed / Probable / False Positive) by the agent or a reviewer.")
    if scanner.skipped.get("too_large") or scanner.skipped.get("max_files_reached"):
        pending.append("Some files were skipped due to size/count limits; see scan.files_skipped_by_reason.")

    return {
        "schema_version": C.SCHEMA_VERSION,
        "tool": {"name": C.TOOL_NAME, "version": C.TOOL_VERSION, "component": "scan_repository"},
        "generated_at": C.utc_now(),
        "stage": "scan",
        "scan": {
            "target": display_target(root) if not single_file else f"{display_target(root)}/{single_file}",
            "mode": args.mode,
            "files_scanned": scanner.files_scanned,
            "files_skipped": sum(scanner.skipped.values()),
            "files_skipped_by_reason": dict(sorted(scanner.skipped.items())),
            "changed_files_only": only is not None and args.mode == "pr",
            "limits": {"max_file_bytes": args.max_file_bytes, "max_files": args.max_files},
            "network": {"osv": bool(args.osv), "external_tools": sorted(external_status)},
            "rules_evaluated": len(scanner.rules),
        },
        "inventory": {
            "languages": dict(sorted(scanner.languages.items(), key=lambda kv: (-kv[1], kv[0]))),
            "frameworks": sorted(scanner.frameworks),
            "auth_mechanisms": sorted(scanner.auth),
            "entry_points": sorted(scanner.entrypoints)[:50],
            "route_handlers_detected": scanner.route_count,
            "config_files": sorted(scanner.config_files)[:100],
            "manifests": sorted(m for m, _ in scanner.manifests),
        },
        "coverage": coverage,
        "pending_verifications": pending,
        "tool_errors": tool_errors,
        "dependencies": dependencies,
        "findings": findings,
        "summary": C.summarize(findings),
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Secure Code Reviewer heuristic scanner (read-only, offline by default).")
    ap.add_argument("target", help="directory or file to scan")
    ap.add_argument("--mode", choices=C.MODES, default="full")
    ap.add_argument("--output", "-o", help="output JSON path (default: stdout)")
    ap.add_argument("--max-file-bytes", type=int, default=C.DEFAULT_MAX_FILE_BYTES)
    ap.add_argument("--max-files", type=int, default=C.DEFAULT_MAX_FILES)
    ap.add_argument("--exclude", action="append", help="glob pattern to exclude (repeatable)")
    ap.add_argument("--changed-files-from", help="pr mode: file with one changed path per line (relative to target)")
    ap.add_argument("--git-diff", metavar="BASE_REF", help="pr mode: compute changed files with git diff BASE...HEAD")
    ap.add_argument("--osv", action="store_true", help="query api.osv.dev with package names/versions (network)")
    ap.add_argument("--external", help="comma-separated installed tools to run: semgrep,gitleaks,trivy")
    ap.add_argument("--semgrep-config", default="p/default", help="semgrep --config value (default: p/default)")
    ap.add_argument("--tool-timeout", type=int, default=600, help="timeout in seconds for network/external tools")
    ap.add_argument("--allow-write-in-target", action="store_true", help="allow --output inside the scanned tree")
    args = ap.parse_args(argv)
    if args.max_file_bytes <= 0 or args.max_files <= 0:
        ap.error("limits must be positive")
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        doc = build_document(args)
        errors = C.validate_document(doc)
        if errors:  # defensive: never emit an invalid document silently
            sys.stderr.write("internal error: produced an invalid document:\n" + "\n".join(errors[:20]) + "\n")
            return 2
        target = Path(args.target).resolve()
        C.write_output(C.dump_json(doc), args.output, target if target.is_dir() else target.parent,
                       args.allow_write_in_target)
    except (FileNotFoundError, ValueError, RuntimeError, PermissionError, OSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    s = doc["summary"]
    sys.stderr.write(f"scanned {doc['scan']['files_scanned']} files; {s['total']} candidate findings "
                     f"({', '.join(f'{k}: {v}' for k, v in s['by_severity'].items() if v)}); "
                     f"{len(doc['tool_errors'])} tool errors\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
