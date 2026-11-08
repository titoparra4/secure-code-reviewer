"""Shared helpers for Secure Code Reviewer scripts.

Standard library only. Compatible with Python 3.9+.

This module contains:
  * constants (severities, statuses, limits),
  * secret redaction used for *every* snippet that leaves the scanner,
  * stable fingerprinting and SCR-NNNN identifier assignment,
  * a dependency-free validator that mirrors schemas/findings.schema.json.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOL_NAME = "secure-code-reviewer"
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"
INFO_URI = "https://github.com/titoparra4/secure-code-reviewer"

SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower = worse
CONFIDENCES = ["High", "Medium", "Low"]
CONFIDENCE_RANK = {c: i for i, c in enumerate(CONFIDENCES)}
STATUSES = ["Confirmed", "Probable", "Needs Manual Review", "False Positive", "Not Verified"]
PRIORITIES = ["P1", "P2", "P3", "P4"]
EFFORTS = ["Low", "Medium", "High"]
SOURCES = ["scanner", "semgrep", "gitleaks", "trivy", "osv", "agent", "manual"]
VULN_STATUSES = ["Not Verified", "No Known Vulnerabilities", "Vulnerable"]
MODES = ["quick", "full", "pr", "api", "secrets", "dependencies", "config"]

DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_FILES = 20_000
MAX_SNIPPET_CHARS = 240
MAX_JSON_INPUT_BYTES = 50_000_000

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "dist", "build",
    "out", "target", "bin", "obj", ".venv", "venv", "env", "__pycache__", ".tox", ".nox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".next", ".nuxt", "coverage",
    ".terraform", ".gradle", ".idea", ".vscode", "site-packages",
}
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz", ".pdf", ".zip",
    ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".ear", ".class", ".dll",
    ".exe", ".so", ".dylib", ".o", ".a", ".pyc", ".pyo", ".woff", ".woff2", ".ttf", ".otf",
    ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wav", ".sqlite", ".db", ".min.js", ".map",
}

TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|fixtures?|testdata|test_data|mocks?|examples?|samples?|demo)(/|$)"
    r"|(^|/)[^/]*(_test|\.test|\.spec|_spec)\.[a-z]+$|(^|/)test_[^/]+$",
    re.IGNORECASE,
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# --------------------------------------------------------------------------- time

def utc_now() -> str:
    """ISO-8601 UTC timestamp. Honors SOURCE_DATE_EPOCH for reproducible output."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        moment = _dt.datetime.fromtimestamp(int(epoch), tz=_dt.timezone.utc)
    else:
        moment = _dt.datetime.now(tz=_dt.timezone.utc)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- secrets

# Placeholder markers: a value containing one of these is treated as a template, not a secret.
PLACEHOLDER_MARKERS = (
    "example", "changeme", "change_me", "change-me", "placeholder", "your_", "your-", "yourkey",
    "<", ">", "${", "{{", "%(", "$(", "xxxx", "****", "dummy", "redacted", "todo", "replace_",
    "replace-", "insert_", "sample", "process.env", "os.environ", "getenv", "env(", "secrets.",
)


def is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    if not v:
        return True
    if any(marker in v for marker in PLACEHOLDER_MARKERS):
        return True
    if len(set(v)) <= 2:  # "aaaaaaaa", "........"
        return True
    if v.startswith("$") and re.fullmatch(r"\$\{?[a-z_][a-z0-9_]*\}?", v):
        return True
    return False


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    import math

    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# (kind, regex, value_group, visible_prefix_regex)
# visible_prefix_regex marks a *public vendor prefix* that may be shown; secret material never is.
SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]", int, Optional[str]]] = [
    ("aws-access-key-id", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1, r"^(AKIA|ASIA)"),
    ("aws-secret-access-key", re.compile(
        r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), 1, None),
    ("github-token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"), 1, r"^gh[pousr]_"),
    ("github-fine-grained-pat", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"), 1, r"^github_pat_"),
    ("gitlab-token", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})"), 1, r"^glpat-"),
    ("slack-token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})"), 1, r"^xox[abposr]-"),
    ("slack-webhook", re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,})"), 1,
     r"^https://hooks\.slack\.com/services/"),
    ("stripe-live-key", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})"), 1, r"^(sk|rk)_live_"),
    ("stripe-test-key", re.compile(r"\b((?:sk|rk)_test_[A-Za-z0-9]{20,})"), 1, r"^(sk|rk)_test_"),
    ("google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"), 1, r"^AIza"),
    ("llm-api-key", re.compile(r"\b(sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{32,})"), 1, r"^sk-(ant-|proj-)?"),
    ("private-key", re.compile(
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), 1, None),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,})"), 1, r"^eyJ"),
    ("connection-string-password", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)"
        r"://[^\s:/@'\"]+:([^\s@'\"/]+)@[^\s'\"]+"), 1, None),
    ("dotnet-connection-string-password", re.compile(
        r"(?i)(?:server|data source|host)\s*=[^;\"']*;[^\"']*?(?:password|pwd)\s*=\s*([^;'\"\s]{3,})"), 1, None),
    ("generic-secret-assignment", re.compile(
        r"(?i)\b([A-Za-z0-9_.-]*(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|access[_-]?key|"
        r"private[_-]?key|client[_-]?secret|auth[_-]?key|signing[_-]?key)[A-Za-z0-9_.-]*)[\"']?\s*"
        r"(?:[:=]|=>|:=)\s*[\"']([^\"'\s]{6,})[\"']"), 2, None),
]

GENERIC_NAME_EXCLUDE = re.compile(
    r"(?i)(url|uri|path|file|filename|name|type|header|field|length|len|env|var|_id|label|placeholder|"
    r"regex|pattern|endpoint|prompt|hint|format|prefix|suffix|mode|expir\w*|ttl|count|limit|policy|"
    r"provider|method|scheme|kind|version|algorithm|alg|location|class)$"
)
PASSWORDISH = re.compile(r"(?i)pass|pwd")


def redact_value(value: str, kind: str, visible_prefix: Optional[str] = None) -> str:
    """Return a non-reversible placeholder. Only a public vendor prefix may remain visible."""
    prefix = ""
    if visible_prefix:
        m = re.match(visible_prefix, value)
        if m:
            prefix = m.group(0)
    return f"{prefix}[REDACTED:{kind}:len={len(value)}]"


def redact_secrets(text: str) -> str:
    """Redact every secret-like value in ``text``. Applied to all evidence snippets."""
    out = text
    for kind, pattern, group, visible in SECRET_PATTERNS:
        def _sub(m: "re.Match[str]") -> str:
            whole = m.group(0)
            value = m.group(group)
            if value is None or "[REDACTED:" in value:
                return whole
            if kind == "generic-secret-assignment" and (is_placeholder(value) or len(value) < 6):
                return whole
            if kind == "private-key":
                return whole  # header only; key material is never captured line-by-line
            start = m.start(group) - m.start(0)
            end = m.end(group) - m.start(0)
            return whole[:start] + redact_value(value, kind, visible) + whole[end:]
        out = pattern.sub(_sub, out)
    return out


def sanitize_text(text: str, limit: int = MAX_SNIPPET_CHARS) -> str:
    """Strip control/ANSI characters, redact secrets and truncate."""
    text = _ANSI_RE.sub("", text)
    text = _CTRL_RE.sub("", text)
    text = text.replace("\t", "    ").strip()
    text = redact_secrets(text)
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


# --------------------------------------------------------------------------- ids

def normalize_for_fingerprint(text: str) -> str:
    return re.sub(r"\s+", " ", redact_secrets(text)).strip().lower()


def fingerprint(rule_id: str, rel_path: str, snippet: str, occurrence: int = 0) -> str:
    """Line-number independent fingerprint, stable across re-runs and unrelated edits."""
    material = f"{rule_id}|{rel_path}|{normalize_for_fingerprint(snippet)}|{occurrence}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def finding_sort_key(f: Dict[str, Any]) -> Tuple[Any, ...]:
    loc = f.get("location") or {}
    return (
        SEVERITY_RANK.get(f.get("severity"), 99),
        CONFIDENCE_RANK.get(f.get("confidence"), 99),
        loc.get("file", ""),
        loc.get("start_line", 0),
        f.get("rule_id", ""),
        f.get("fingerprint", ""),
    )


def assign_ids(findings: List[Dict[str, Any]], baseline: Optional[Dict[str, str]] = None) -> None:
    """Assign SCR-NNNN ids in place.

    Ids already present in ``baseline`` (fingerprint -> id) are reused. New findings get the next
    free number, in a deterministic order, so the same input always yields the same ids.
    """
    baseline = baseline or {}
    used = set(baseline.values())
    next_num = 1 + max((int(i.split("-")[1]) for i in used if re.fullmatch(r"SCR-\d+", i)), default=0)
    for f in sorted(findings, key=finding_sort_key):
        fp = f["fingerprint"]
        if fp in baseline:
            f["id"] = baseline[fp]
        else:
            f["id"] = f"SCR-{next_num:04d}"
            next_num += 1


def remediation_priority(severity: str, confidence: str, status: str) -> str:
    """Documented in references/severity-classification.md (Remediation priority)."""
    if status == "False Positive" or severity == "Informational":
        return "P4"
    sev = SEVERITY_RANK.get(severity, 4)
    conf = CONFIDENCE_RANK.get(confidence, 2)
    strong_status = status in ("Confirmed", "Probable")
    if sev <= 1 and conf == 0 and strong_status:
        return "P1"
    if sev == 0 or (sev == 1 and conf <= 1) or (sev == 2 and conf == 0 and strong_status):
        return "P2"
    if sev <= 3:
        return "P3"
    return "P4"


def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_sev = {s: 0 for s in SEVERITIES}
    by_status = {s: 0 for s in STATUSES}
    by_priority = {p: 0 for p in PRIORITIES}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
        by_priority[f["remediation_priority"]] = by_priority.get(f["remediation_priority"], 0) + 1
    active = [f for f in findings if f["status"] != "False Positive"]
    return {
        "total": len(findings),
        "active": len(active),
        "by_severity": by_sev,
        "by_status": by_status,
        "by_priority": by_priority,
    }


# --------------------------------------------------------------------------- paths & io

def is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def is_test_path(rel_path: str) -> bool:
    return bool(TEST_PATH_RE.search(rel_path.replace("\\", "/")))


def load_json_file(path: str) -> Any:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"input file not found: {path}")
    if p.stat().st_size > MAX_JSON_INPUT_BYTES:
        raise ValueError(f"input file too large: {path}")
    with p.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_output(text: str, output: Optional[str], target_root: Optional[Path] = None,
                 allow_write_in_target: bool = False) -> None:
    """Write to stdout or a file. Refuses to write inside the audited tree unless allowed."""
    if not output or output == "-":
        import sys

        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return
    out = Path(output)
    if target_root is not None and not allow_write_in_target:
        if is_within(target_root, out.parent if not out.exists() else out):
            raise PermissionError(
                f"refusing to write '{output}' inside the audited target; "
                "choose another path or pass --allow-write-in-target"
            )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")


def dump_json(doc: Any) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False)


# --------------------------------------------------------------------------- validation

ID_RE = re.compile(r"^SCR-\d{4,}$")
CWE_RE = re.compile(r"^CWE-\d+$")
FP_RE = re.compile(r"^[0-9a-f]{16,64}$")
REL_PATH_RE = re.compile(r"^(?!/)(?![A-Za-z]:)(?!.*(^|/)\.\.(/|$)).+$")


def _req(obj: Dict[str, Any], keys: Iterable[str], where: str, errors: List[str]) -> None:
    for k in keys:
        if k not in obj:
            errors.append(f"{where}: missing required field '{k}'")


def validate_finding(f: Any, where: str = "finding") -> List[str]:
    errors: List[str] = []
    if not isinstance(f, dict):
        return [f"{where}: must be an object"]
    _req(f, ["id", "fingerprint", "rule_id", "title", "category", "severity", "confidence", "status",
             "cwe", "owasp_category", "location", "evidence", "impact", "remediation", "source",
             "remediation_priority"], where, errors)
    if errors:
        return errors
    if not ID_RE.match(str(f["id"])):
        errors.append(f"{where}: id '{f['id']}' does not match SCR-NNNN")
    if not FP_RE.match(str(f["fingerprint"])):
        errors.append(f"{where}: invalid fingerprint")
    if f["severity"] not in SEVERITIES:
        errors.append(f"{where}: invalid severity '{f['severity']}'")
    if f["confidence"] not in CONFIDENCES:
        errors.append(f"{where}: invalid confidence '{f['confidence']}'")
    if f["status"] not in STATUSES:
        errors.append(f"{where}: invalid status '{f['status']}'")
    if f["source"] not in SOURCES:
        errors.append(f"{where}: invalid source '{f['source']}'")
    if f["remediation_priority"] not in PRIORITIES:
        errors.append(f"{where}: invalid remediation_priority")
    if not CWE_RE.match(str(f["cwe"])):
        errors.append(f"{where}: cwe must look like CWE-123")
    for key in ("title", "category", "owasp_category", "impact", "rule_id"):
        if not isinstance(f.get(key), str) or not f[key].strip():
            errors.append(f"{where}: '{key}' must be a non-empty string")
    loc = f["location"]
    if not isinstance(loc, dict):
        errors.append(f"{where}: location must be an object")
    else:
        _req(loc, ["file", "start_line", "end_line"], f"{where}.location", errors)
        if isinstance(loc.get("file"), str) and not REL_PATH_RE.match(loc["file"]):
            errors.append(f"{where}.location.file must be a relative path inside the target")
        s, e = loc.get("start_line"), loc.get("end_line")
        if not (isinstance(s, int) and isinstance(e, int) and s >= 1 and e >= s):
            errors.append(f"{where}.location: start_line/end_line must be integers with 1 <= start <= end")
    ev = f["evidence"]
    if not isinstance(ev, dict):
        errors.append(f"{where}: evidence must be an object")
    else:
        _req(ev, ["description", "sanitized_code"], f"{where}.evidence", errors)
        code = ev.get("sanitized_code", "")
        if isinstance(code, str) and redact_secrets(code) != code:
            errors.append(f"{where}.evidence.sanitized_code contains an unredacted secret-like value")
    rem = f["remediation"]
    if not isinstance(rem, dict):
        errors.append(f"{where}: remediation must be an object")
    else:
        _req(rem, ["recommendation", "verification"], f"{where}.remediation", errors)
    if "effort" in f and f["effort"] not in EFFORTS:
        errors.append(f"{where}: invalid effort")
    if "cvss" in f and f["cvss"] is not None:
        c = f["cvss"]
        if not isinstance(c, dict) or c.get("version") != "4.0" or not str(c.get("vector", "")).startswith("CVSS:4.0/"):
            errors.append(f"{where}: cvss must be {{version: '4.0', vector: 'CVSS:4.0/...'}}")
        elif c.get("score") is not None and not (isinstance(c["score"], (int, float)) and 0 <= c["score"] <= 10):
            errors.append(f"{where}: cvss.score must be between 0 and 10")
    tri = f.get("triage")
    if tri is not None:
        if not isinstance(tri, dict) or not str(tri.get("justification", "")).strip():
            errors.append(f"{where}: triage requires a non-empty justification")
    return errors


def validate_document(doc: Any) -> List[str]:
    """Validate a findings document. Returns a list of human-readable errors (empty = valid)."""
    errors: List[str] = []
    if not isinstance(doc, dict):
        return ["document must be a JSON object"]
    _req(doc, ["schema_version", "tool", "generated_at", "stage", "scan", "coverage",
               "pending_verifications", "tool_errors", "dependencies", "findings", "summary"],
         "document", errors)
    if errors:
        return errors
    if doc["schema_version"] != SCHEMA_VERSION:
        errors.append(f"unsupported schema_version {doc['schema_version']}")
    if doc["stage"] not in ("scan", "normalized"):
        errors.append("stage must be 'scan' or 'normalized'")
    scan = doc["scan"]
    if not isinstance(scan, dict):
        errors.append("scan must be an object")
    else:
        _req(scan, ["target", "mode", "files_scanned", "files_skipped"], "scan", errors)
        if scan.get("mode") not in MODES + ["mixed"]:
            errors.append(f"scan.mode invalid: {scan.get('mode')}")
    if not isinstance(doc["coverage"], list):
        errors.append("coverage must be a list")
    else:
        for i, c in enumerate(doc["coverage"]):
            if not isinstance(c, dict) or c.get("status") not in ("reviewed", "partial", "not_reviewed"):
                errors.append(f"coverage[{i}] invalid")
    for i, d in enumerate(doc["dependencies"] if isinstance(doc["dependencies"], list) else []):
        if not isinstance(d, dict):
            errors.append(f"dependencies[{i}] must be an object")
            continue
        _req(d, ["name", "ecosystem", "manifest", "pinned", "vulnerability_status"], f"dependencies[{i}]", errors)
        if d.get("vulnerability_status") not in VULN_STATUSES:
            errors.append(f"dependencies[{i}]: invalid vulnerability_status")
    if not isinstance(doc["findings"], list):
        errors.append("findings must be a list")
        return errors
    seen_ids, seen_fp = set(), set()
    for i, f in enumerate(doc["findings"]):
        errors.extend(validate_finding(f, f"findings[{i}]"))
        if isinstance(f, dict):
            if f.get("id") in seen_ids:
                errors.append(f"findings[{i}]: duplicate id {f.get('id')}")
            if f.get("fingerprint") in seen_fp:
                errors.append(f"findings[{i}]: duplicate fingerprint")
            seen_ids.add(f.get("id"))
            seen_fp.add(f.get("fingerprint"))
    return errors
