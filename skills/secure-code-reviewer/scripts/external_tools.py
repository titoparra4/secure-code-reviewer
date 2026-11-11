"""Optional integration with external scanners (Semgrep, Gitleaks, Trivy).

Tools are used only if already installed and explicitly requested. Nothing is installed.
Each adapter returns (raw_findings, error_or_None). A missing tool is *not* an error: it is
reported as skipped coverage. Execution uses argument lists (no shell) and a timeout.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

RawFinding = Dict[str, Any]
SEMGREP_SEV = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
TRIVY_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Medium"}


def available(tool: str) -> bool:
    return shutil.which(tool) is not None


def _run(cmd: List[str], timeout: int, ok_codes: Tuple[int, ...] = (0,)) -> Tuple[Optional[str], Optional[str]]:
    env = dict(os.environ, SEMGREP_SEND_METRICS="off")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except OSError as exc:
        return None, f"could not start: {type(exc).__name__}"
    if proc.returncode not in ok_codes:
        tail = (proc.stderr or "").strip().splitlines()[-1:] or [""]
        return None, f"exit code {proc.returncode}: {tail[0][:200]}"
    return proc.stdout, None


def _rel(root: Path, path: str) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(root.resolve()).as_posix() if p.is_absolute() else p.as_posix().lstrip("./")
    except ValueError:
        return p.name


def run_semgrep(root: Path, config: str, timeout: int = 600) -> Tuple[List[RawFinding], Optional[str]]:
    out, err = _run(["semgrep", "scan", "--json", "--metrics=off", "--quiet", "--config", config, str(root)],
                    timeout, ok_codes=(0, 1))
    if err:
        return [], err
    try:
        data = json.loads(out or "{}")
    except ValueError:
        return [], "invalid JSON output"
    results: List[RawFinding] = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        cwe_list = meta.get("cwe") or []
        cwe = "CWE-20"
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        for c in cwe_list:
            if isinstance(c, str) and c.upper().startswith("CWE-"):
                cwe = "CWE-" + "".join(ch for ch in c[4:].split(":")[0] if ch.isdigit())
                break
        owasp = meta.get("owasp")
        if isinstance(owasp, list):
            owasp = owasp[0] if owasp else None
        results.append({
            "rule_id": f"semgrep.{r.get('check_id', 'unknown')}",
            "title": (extra.get("message") or r.get("check_id", "Semgrep finding")).split("\n")[0][:160],
            "category": "Static Analysis (Semgrep)",
            "severity": SEMGREP_SEV.get(str(extra.get("severity", "")).upper(), "Medium"),
            "confidence": str(meta.get("confidence", "Medium")).capitalize() if str(meta.get("confidence", "")).upper() in ("HIGH", "MEDIUM", "LOW") else "Medium",
            "cwe": cwe,
            "owasp_category": owasp or "Unmapped",
            "file": _rel(root, r.get("path", "")),
            "start_line": int((r.get("start") or {}).get("line", 1)),
            "end_line": int((r.get("end") or {}).get("line", (r.get("start") or {}).get("line", 1))),
            "snippet": extra.get("lines", ""),
            "description": (extra.get("message") or "")[:500],
            "source": "semgrep",
        })
    return results, None


def run_gitleaks(root: Path, timeout: int = 600) -> Tuple[List[RawFinding], Optional[str]]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        out, err = _run(["gitleaks", "dir", str(root), "--report-format", "json", "--report-path", str(report),
                         "--redact", "--no-banner", "--exit-code", "0"], timeout)
        if err and "unknown command" in err.lower():
            out, err = _run(["gitleaks", "detect", "--no-git", "--source", str(root), "--report-format", "json",
                             "--report-path", str(report), "--redact", "--no-banner", "--exit-code", "0"], timeout)
        if err:
            return [], err
        try:
            data = json.loads(report.read_text(encoding="utf-8") or "[]")
        except (OSError, ValueError):
            return [], "invalid JSON report"
    results: List[RawFinding] = []
    for r in data or []:
        results.append({
            "rule_id": f"gitleaks.{r.get('RuleID', 'secret')}",
            "title": f"Secret detected by Gitleaks: {r.get('Description', r.get('RuleID', 'secret'))}"[:160],
            "category": "Secrets",
            "severity": "High",
            "confidence": "Medium",
            "cwe": "CWE-798",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "file": _rel(root, r.get("File", "")),
            "start_line": int(r.get("StartLine") or 1),
            "end_line": int(r.get("EndLine") or r.get("StartLine") or 1),
            "snippet": "",  # never copy Match/Secret fields, even when redacted
            "description": "Gitleaks rule matched; value withheld.",
            "source": "gitleaks",
            "profile": "secret",
        })
    return results, None


def run_trivy(root: Path, timeout: int = 900) -> Tuple[List[RawFinding], Optional[str]]:
    out, err = _run(["trivy", "fs", "--format", "json", "--quiet", "--scanners", "vuln,misconfig", str(root)], timeout)
    if err:
        return [], err
    try:
        data = json.loads(out or "{}")
    except ValueError:
        return [], "invalid JSON output"
    results: List[RawFinding] = []
    for res in data.get("Results", []) or []:
        target = _rel(root, res.get("Target", ""))
        for v in res.get("Vulnerabilities", []) or []:
            fixed = v.get("FixedVersion")
            results.append({
                "rule_id": f"trivy.{v.get('VulnerabilityID', 'vuln')}",
                "title": f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('VulnerabilityID')}"[:160],
                "category": "Vulnerable Dependency",
                "severity": TRIVY_SEV.get(str(v.get("Severity", "")).upper(), "Medium"),
                "confidence": "High",
                "cwe": (v.get("CweIDs") or ["CWE-1395"])[0],
                "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                "file": target, "start_line": 1, "end_line": 1,
                "snippet": f"{v.get('PkgName')}=={v.get('InstalledVersion')}",
                "description": (v.get("Title") or "")[:300] + (f" Fixed in: {fixed}." if fixed else ""),
                "source": "trivy",
            })
        for m in res.get("Misconfigurations", []) or []:
            cause = m.get("CauseMetadata") or {}
            start = int(cause.get("StartLine") or 1)
            results.append({
                "rule_id": f"trivy.{m.get('ID', 'misconfig')}",
                "title": (m.get("Title") or m.get("ID") or "Misconfiguration")[:160],
                "category": "Infrastructure Misconfiguration",
                "severity": TRIVY_SEV.get(str(m.get("Severity", "")).upper(), "Medium"),
                "confidence": "Medium", "cwe": "CWE-16",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "file": target, "start_line": start, "end_line": int(cause.get("EndLine") or start),
                "snippet": "", "description": (m.get("Message") or "")[:300], "source": "trivy",
            })
    return results, None


RUNNERS = {"semgrep": run_semgrep, "gitleaks": run_gitleaks, "trivy": run_trivy}
