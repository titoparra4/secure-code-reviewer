#!/usr/bin/env python3
"""Render a findings document as Markdown, JSON or SARIF 2.1.0.

All text coming from findings is treated as untrusted: it is escaped for Markdown tables,
HTML-significant characters are neutralized, and code is placed in fences that cannot be
broken out of. Secrets are redacted again defensively before rendering.

Exit codes: 0 = ok, 2 = invalid input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scr_common as C  # noqa: E402

DEFAULT_TEMPLATE = Path(__file__).resolve().parent.parent / "assets" / "report-template.md"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SECURITY_SEVERITY = {"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "3.0", "Informational": "0.0"}
SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Informational": "note"}


# --------------------------------------------------------------------------- escaping

def text(value: Any) -> str:
    """Escape free text for Markdown paragraphs."""
    s = C.redact_secrets(str(value if value is not None else ""))
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_\[\]])", r"\\\1", s)


def cell(value: Any) -> str:
    """Escape for a Markdown table cell (single line, no pipes)."""
    return text(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def code_block(value: str, lang: str = "") -> str:
    body = C.redact_secrets(value or "").replace("```", "ʼʼʼ")
    return f"```{lang}\n{body}\n```"


def loc(f: Dict[str, Any]) -> str:
    l = f["location"]
    lines = str(l["start_line"]) if l["start_line"] == l["end_line"] else f"{l['start_line']}-{l['end_line']}"
    return f"{l['file']}:{lines}"


# --------------------------------------------------------------------------- markdown sections

def active(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [f for f in doc["findings"] if f["status"] != "False Positive"]


def executive_summary(doc: Dict[str, Any]) -> str:
    act = active(doc)
    scan = doc["scan"]
    sev_counts = {s: sum(1 for f in act if f["severity"] == s) for s in C.SEVERITIES}
    strong = [f for f in act if f["status"] in ("Confirmed", "Probable")]
    overall = next((s for s in C.SEVERITIES if any(f["severity"] == s for f in strong)), "None identified")
    out = ["**Scope.** Target `" + cell(scan["target"]) + f"` in `{scan['mode']}` mode; "
           f"{scan['files_scanned']} files analyzed, {scan['files_skipped']} skipped."]
    net = scan.get("network") or {}
    out.append("Network lookups: " + ("OSV advisory database" if net.get("osv") else "none (offline)") +
               (f"; external tools: {', '.join(net.get('external_tools') or [])}" if net.get("external_tools") else "") + ".")
    inv = doc.get("inventory") or {}
    if inv:
        langs = ", ".join(f"{k} ({v})" for k, v in list(inv.get("languages", {}).items())[:6]) or "n/a"
        out.append(f"Stack: {cell(langs)}; frameworks: {cell(', '.join(inv.get('frameworks', [])) or 'none detected')}; "
                   f"auth mechanisms: {cell(', '.join(inv.get('auth_mechanisms', [])) or 'none detected')}.")
    out.append("")
    out.append(f"**Risk summary.** Highest severity among Confirmed/Probable findings: **{overall}**. "
               f"Active findings: {len(act)} (" + ", ".join(f"{k}: {v}" for k, v in sev_counts.items() if v) + "). "
               f"Confirmed: {sum(f['status'] == 'Confirmed' for f in act)}, Probable: {sum(f['status'] == 'Probable' for f in act)}, "
               f"Needs Manual Review: {sum(f['status'] == 'Needs Manual Review' for f in act)}, "
               f"False Positives (excluded): {sum(f['status'] == 'False Positive' for f in doc['findings'])}.")
    if doc.get("baseline"):
        b = doc["baseline"]
        out.append(f"Compared to baseline: {b['new']} new, {b['existing']} existing, {len(b['resolved_ids'])} resolved.")
    out.append("")
    top = [f for f in act if f["remediation_priority"] in ("P1", "P2")][:10]
    out.append("**Priority vulnerabilities.**")
    out.append("")
    if top:
        for f in top:
            out.append(f"- `{f['id']}` ({f['remediation_priority']}, {f['severity']}, {f['status']}) — "
                       f"{text(f['title'])} at `{cell(loc(f))}`")
    else:
        out.append("- No P1/P2 findings.")
    out.append("")
    not_reviewed = [c["category"] for c in doc["coverage"] if c["status"] == "not_reviewed"]
    out.append("**Limitations.** Static, heuristic analysis: no code was executed and findings marked Probable or "
               "Needs Manual Review are not exploit-verified. "
               + (f"Not reviewed: {text('; '.join(not_reviewed[:8]))}. " if not_reviewed else "")
               + (f"{len(doc['tool_errors'])} tool error(s) occurred. " if doc["tool_errors"] else ""))
    out.append("")
    out.append("**Recommended actions.**")
    out.append("")
    actions: List[str] = []
    if any(f["category"].startswith("Secrets") for f in act):
        actions.append("Treat detected credentials as compromised until proven otherwise: revoke/rotate them, review provider logs, then remove them from code and history.")
    if any(f["remediation_priority"] == "P1" for f in act):
        actions.append("Fix P1 findings first, adding the proposed regression tests with each fix.")
    if any(f["status"] == "Needs Manual Review" for f in act):
        actions.append("Triage the 'Needs Manual Review' findings and record decisions (with justification) in a triage file.")
    if any(d["vulnerability_status"] == "Not Verified" for d in doc["dependencies"]):
        actions.append("Verify dependencies against an advisory database (re-run with --osv, or use OSV-Scanner/Dependabot/Trivy).")
    actions.append("Review authorization (object ownership/IDOR, role checks) and business logic manually; pattern rules cannot assess them.")
    out.extend(f"{i}. {a}" for i, a in enumerate(actions, 1))
    return "\n".join(out)


def findings_table(doc: Dict[str, Any]) -> str:
    act = active(doc)
    if not act:
        return "_No active findings._"
    rows = ["| ID | Severity | Finding | File | Confidence | Status | Priority |", "|---|---|---|---|---|---|---|"]
    for f in act:
        rows.append(f"| {f['id']} | {f['severity']} | {cell(f['title'])} | `{cell(loc(f))}` | {f['confidence']} | "
                    f"{f['status']} | {f['remediation_priority']} |")
    return "\n".join(rows)


def detailed(doc: Dict[str, Any]) -> str:
    parts: List[str] = []
    for f in active(doc):
        rem = f["remediation"]
        lang = Path(f["location"]["file"]).suffix.lstrip(".")
        p = [f"### {f['id']} — {text(f['title'])}", "",
             "| Attribute | Value |", "|---|---|",
             f"| Severity / Confidence | {f['severity']} / {f['confidence']} |",
             f"| Status | {f['status']} |",
             f"| Remediation priority | {f['remediation_priority']} (effort: {f.get('effort', 'n/a')}) |",
             f"| CWE | [{f['cwe']}](https://cwe.mitre.org/data/definitions/{f['cwe'].split('-')[1]}.html) |",
             f"| OWASP | {cell(f['owasp_category'])}" + (f"; {cell(f['owasp_api_category'])}" if f.get("owasp_api_category") else "") + " |",
             f"| Location | `{cell(loc(f))}` |",
             f"| Source | {cell(', '.join(f.get('sources', [f['source']])))} (rule `{cell(f['rule_id'])}`) |"]
        if f.get("cvss"):
            p.append(f"| CVSS v4.0 | `{cell(f['cvss'].get('vector'))}`" +
                     (f" — {f['cvss']['score']}" if f["cvss"].get("score") is not None else " (score not computed)") + " |")
        if f.get("baseline_status"):
            p.append(f"| Baseline | {f['baseline_status']} |")
        p += ["", "**Evidence (sanitized)**", "", code_block(f["evidence"]["sanitized_code"], lang), "",
              f"**Technical explanation.** {text(f['evidence']['description'])}", "",
              f"**Potential impact.** {text(f['impact'])}", "",
              f"**Exploitation conditions.** {text(f.get('exploitability', 'Not assessed.'))}", "",
              f"**Business impact.** {text(f.get('business_impact', 'Not assessed.'))}", "",
              f"**Recommended fix.** {text(rem['recommendation'])}", ""]
        if rem.get("fixed_code_example"):
            # generic profile examples may be in another language than the file: no language tag
            p += ["**Corrected code (illustrative example; adapt to the project's language and framework).**", "",
                  code_block(rem["fixed_code_example"]), ""]
        if rem.get("security_test"):
            p += [f"**Security test.** {text(rem['security_test'])}", ""]
        if rem.get("regression_test"):
            p += [f"**Regression test.** {text(rem['regression_test'])}", ""]
        ver = f.get("verification") or {}
        notes = "; ".join(ver.get("notes") or [])
        p += [f"**Verification status.** {f['status']} — method: {ver.get('method', 'n/a')}, "
              f"reproduced: {'yes' if ver.get('reproduced') else 'no'}" + (f" ({text(notes)})" if notes else "") +
              f". To verify the fix: {text(rem['verification'])}", ""]
        if f.get("triage"):
            t = f["triage"]
            p += [f"**Triage.** Originally {t['original_severity']} / {t['original_status']}; "
                  f"justification: {text(t['justification'])} (reviewer: {text(t['reviewer'])})", ""]
        parts.append("\n".join(p))
    return "\n---\n\n".join(parts) if parts else "_No active findings._"


def coverage(doc: Dict[str, Any]) -> str:
    rows = ["| Category | Status | Method | Notes |", "|---|---|---|---|"]
    for c in doc["coverage"]:
        rows.append(f"| {cell(c['category'])} | {c['status']} | {cell(c.get('method', ''))} | {cell(c.get('notes', ''))} |")
    rows.append("")
    rows.append("_`partial` = checked with heuristics or tools that cannot prove absence of issues; "
                "`reviewed` = verified by an agent or human reviewer; `not_reviewed` = outside this run._")
    return "\n".join(rows)


def dependencies(doc: Dict[str, Any]) -> str:
    deps = doc["dependencies"]
    if not deps:
        return "_No dependency manifests analyzed in this run._"
    rows = ["| Package | Ecosystem | Spec | Resolved version | Manifest | Vulnerability status |", "|---|---|---|---|---|---|"]
    for d in deps[:200]:
        adv = ", ".join(a["id"] for a in d.get("advisories", [])[:5])
        rows.append(f"| {cell(d['name'])} | {d['ecosystem']} | `{cell(d.get('spec') or '-')}` | {cell(d.get('version') or '-')} | "
                    f"`{cell(d['manifest'])}` | {d['vulnerability_status']}{(' — ' + cell(adv)) if adv else ''} |")
    if len(deps) > 200:
        rows.append(f"\n_{len(deps) - 200} more dependencies omitted; see the JSON report._")
    if any(d["vulnerability_status"] == "Not Verified" for d in deps):
        rows.append("\n_**Not Verified** means no advisory lookup was performed or the version could not be resolved. "
                    "It does not mean the package is safe._")
    return "\n".join(rows)


def roadmap(doc: Dict[str, Any]) -> str:
    act = active(doc)
    effort_rank = {"Low": 0, "Medium": 1, "High": 2}
    out: List[str] = []
    labels = {"P1": "Immediately", "P2": "Next sprint", "P3": "Planned hardening", "P4": "Backlog / informational"}
    for prio in C.PRIORITIES:
        items = sorted([f for f in act if f["remediation_priority"] == prio],
                       key=lambda f: (effort_rank.get(f.get("effort", "Medium"), 1), C.finding_sort_key(f)))
        if not items:
            continue
        out += [f"**{prio} — {labels[prio]}**", "", "| ID | Finding | Effort | Dependencies / notes |", "|---|---|---|---|"]
        for f in items:
            note = ""
            if f["category"].startswith("Secrets"):
                note = "Rotate first; then remove from code and history"
            elif f["category"] in ("Container Security", "Infrastructure Exposure"):
                note = "Validate in a non-production environment before rollout"
            elif f.get("related_rules"):
                note = "Fix together with related rules: " + ", ".join(f["related_rules"])
            out.append(f"| {f['id']} | {cell(f['title'])} | {f.get('effort', 'n/a')} | {cell(note) or '-'} |")
        out.append("")
    out.append("_Order within each priority favors low-effort fixes first. Priorities follow "
               "references/severity-classification.md._")
    return "\n".join(out) if act else "_Nothing to remediate in this run._"


def limitations(doc: Dict[str, Any]) -> str:
    out = ["- Heuristic pattern rules and intra-file, name-based taint tracking can miss vulnerabilities "
           "(false negatives) and flag safe code (false positives).",
           "- No code from the target was executed; runtime configuration, deployed infrastructure and "
           "secrets managers were not inspected.",
           "- A static review cannot establish compliance with any standard (OWASP ASVS, PCI DSS, ISO 27001, etc.)."]
    for p in doc["pending_verifications"]:
        out.append(f"- Pending: {text(p)}")
    for e in doc["tool_errors"]:
        out.append(f"- Tool error ({text(e.get('tool', '?'))}): {text(e.get('message', ''))}")
    return "\n".join(out)


def appendix(doc: Dict[str, Any]) -> str:
    fps = [f for f in doc["findings"] if f["status"] == "False Positive"]
    if not fps:
        return ""
    rows = ["## Appendix A — Findings triaged as False Positive", "", "| ID | Finding | File | Justification |", "|---|---|---|---|"]
    for f in fps:
        rows.append(f"| {f['id']} | {cell(f['title'])} | `{cell(loc(f))}` | {cell((f.get('triage') or {}).get('justification', '-'))} |")
    return "\n".join(rows)


def render_markdown(doc: Dict[str, Any], template: str) -> str:
    values = {
        "target": cell(doc["scan"]["target"]), "tool_version": C.TOOL_VERSION, "generated_at": doc["generated_at"],
        "mode": doc["scan"]["mode"], "stage": doc["stage"], "executive_summary": executive_summary(doc),
        "findings_table": findings_table(doc), "detailed_findings": detailed(doc), "coverage": coverage(doc),
        "dependencies": dependencies(doc), "roadmap": roadmap(doc), "limitations": limitations(doc),
        "appendix": appendix(doc),
    }
    return re.sub(r"\{\{(\w+)\}\}", lambda m: values.get(m.group(1), m.group(0)), template).rstrip() + "\n"


# --------------------------------------------------------------------------- SARIF

def render_sarif(doc: Dict[str, Any], path_prefix: str = "") -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    prefix = path_prefix.strip("/") + "/" if path_prefix.strip("/") else ""
    for f in active(doc):
        rid = f["rule_id"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": re.sub(r"[^A-Za-z0-9]", "", f["title"].title())[:80] or "Finding",
                "shortDescription": {"text": f["title"][:200]},
                "fullDescription": {"text": f["evidence"]["description"][:1000]},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f['cwe'].split('-')[1]}.html",
                "help": {"text": f["remediation"]["recommendation"][:2000]},
                "properties": {"tags": ["security", f["cwe"], f["category"]],
                               "security-severity": SECURITY_SEVERITY[f["severity"]]},
            }
        else:  # keep the highest severity seen for the rule
            cur = float(rules[rid]["properties"]["security-severity"])
            rules[rid]["properties"]["security-severity"] = str(max(cur, float(SECURITY_SEVERITY[f["severity"]])))
        results.append({
            "ruleId": rid,
            "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"[{f['id']}] {f['title']} ({f['severity']}, confidence {f['confidence']}, {f['status']}). "
                                f"{f['remediation']['recommendation']}"[:2000]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": prefix + f["location"]["file"], "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": f["location"]["start_line"], "endLine": f["location"]["end_line"]}}}],
            "partialFingerprints": {"secureCodeReviewer/v1": f["fingerprint"]},
            "properties": {"scrId": f["id"], "severity": f["severity"], "confidence": f["confidence"],
                           "status": f["status"], "priority": f["remediation_priority"], "owasp": f["owasp_category"]},
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Secure Code Reviewer", "semanticVersion": C.TOOL_VERSION,
                                "informationUri": C.INFO_URI, "rules": list(rules.values())}},
            "automationDetails": {"id": f"secure-code-reviewer/{doc['scan']['mode']}/"},
            "results": results,
        }],
    }


def validate_sarif(sarif: Dict[str, Any]) -> List[str]:
    """Structural checks for the SARIF subset we emit (full schema validation happens on upload)."""
    errors: List[str] = []
    if sarif.get("version") != "2.1.0" or not isinstance(sarif.get("runs"), list) or len(sarif["runs"]) != 1:
        return ["SARIF must have version 2.1.0 and exactly one run"]
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for i, r in enumerate(run["results"]):
        if r["ruleId"] not in rule_ids:
            errors.append(f"results[{i}].ruleId not declared in rules")
        if r["level"] not in ("error", "warning", "note", "none"):
            errors.append(f"results[{i}].level invalid")
        region = r["locations"][0]["physicalLocation"]["region"]
        if not (isinstance(region["startLine"], int) and region["startLine"] >= 1 and region["endLine"] >= region["startLine"]):
            errors.append(f"results[{i}] invalid region")
        if not r["message"]["text"]:
            errors.append(f"results[{i}] empty message")
    return errors


# --------------------------------------------------------------------------- CLI

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Render Secure Code Reviewer findings as Markdown, JSON or SARIF.")
    ap.add_argument("input", help="findings document (scan or normalized)")
    ap.add_argument("--format", "-f", choices=["markdown", "json", "sarif"], default="markdown")
    ap.add_argument("--output", "-o", help="output path (default: stdout)")
    ap.add_argument("--template", default=str(DEFAULT_TEMPLATE), help="Markdown template path")
    ap.add_argument("--sarif-path-prefix", default="", help="prefix added to file paths in SARIF (if the scan target was a subdirectory)")
    args = ap.parse_args(argv)
    try:
        doc = C.load_json_file(args.input)
        errors = C.validate_document(doc)
        if errors:
            raise ValueError("invalid findings document:\n  " + "\n  ".join(errors[:20]))
        if args.format == "json":
            out = C.dump_json(doc)
        elif args.format == "sarif":
            sarif = render_sarif(doc, args.sarif_path_prefix)
            serr = validate_sarif(sarif)
            if serr:
                raise ValueError("generated SARIF failed validation: " + "; ".join(serr[:10]))
            out = json.dumps(sarif, indent=2, ensure_ascii=False)
        else:
            out = render_markdown(doc, Path(args.template).read_text(encoding="utf-8"))
        C.write_output(out, args.output)
    except (ValueError, FileNotFoundError, OSError, KeyError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
