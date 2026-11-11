#!/usr/bin/env python3
"""Normalize, correlate and triage findings into a single validated document.

  * merges one or more scan documents,
  * adds agent/manual findings (--add), sanitizing their evidence,
  * correlates duplicates (same file, line and CWE reported by different rules/tools),
  * applies triage decisions (--triage) - every change requires a justification and the
    original values are preserved, so severity can never be lowered silently,
  * keeps SCR ids stable against a previous normalized report (--baseline) and marks
    findings as new/existing, listing resolved ones.

Exit codes: 0 = ok, 2 = invalid input or output.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scr_common as C  # noqa: E402

COVERAGE_ORDER = {"reviewed": 0, "partial": 1, "not_reviewed": 2}
AGENT_REQUIRED = ["title", "severity", "confidence", "status", "cwe", "owasp_category", "location", "evidence",
                  "impact", "remediation"]


class InputError(Exception):
    pass


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "finding"


def load_scan(path: str) -> Dict[str, Any]:
    doc = C.load_json_file(path)
    errors = C.validate_document(doc)
    if errors:
        raise InputError(f"{path} is not a valid findings document:\n  " + "\n  ".join(errors[:20]))
    return doc


def load_agent_coverage(path: str) -> List[Dict[str, Any]]:
    """Optional 'coverage' entries in an --add file record what the agent/human actually reviewed."""
    data = C.load_json_file(path)
    entries = data.get("coverage", []) if isinstance(data, dict) else []
    out = []
    for i, c in enumerate(entries):
        if not isinstance(c, dict) or not c.get("category") or c.get("status") not in COVERAGE_ORDER:
            raise InputError(f"{path}: coverage[{i}] needs 'category' and a valid 'status'")
        out.append({"category": C.sanitize_text(str(c["category"]), 200), "status": c["status"],
                    "method": C.sanitize_text(str(c.get("method", "manual")), 60),
                    "notes": C.sanitize_text(str(c.get("notes", "")), 500)})
    return out


def load_agent_findings(path: str) -> List[Dict[str, Any]]:
    data = C.load_json_file(path)
    items = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise InputError(f"{path}: expected a list of findings or an object with 'findings'")
    out: List[Dict[str, Any]] = []
    for i, raw in enumerate(items):
        where = f"{path}[{i}]"
        if not isinstance(raw, dict):
            raise InputError(f"{where}: finding must be an object")
        missing = [k for k in AGENT_REQUIRED if k not in raw]
        if missing:
            raise InputError(f"{where}: missing fields {missing}")
        f = dict(raw)
        loc = dict(f["location"])
        loc.setdefault("end_line", loc.get("start_line"))
        f["location"] = loc
        ev = dict(f["evidence"])
        ev["sanitized_code"] = C.sanitize_text(str(ev.get("sanitized_code", "")), 600)
        ev["description"] = C.sanitize_text(str(ev.get("description", "")), 1200)
        f["evidence"] = ev
        f.setdefault("rule_id", f"agent.{slug(f['title'])}")
        f.setdefault("category", "Manual Review")
        f.setdefault("source", "agent")
        f.setdefault("exploitability", "Assessed by reviewer; see evidence.")
        f.setdefault("business_impact", "Not assessed; evaluate against the affected asset.")
        f.setdefault("effort", "Medium")
        f.setdefault("cvss", None)
        f.setdefault("references", [f"https://cwe.mitre.org/data/definitions/{str(f['cwe']).split('-')[-1]}.html"])
        f.setdefault("verification", {"method": "manual", "tool": f["source"], "reproduced": False, "notes": []})
        f["fingerprint"] = f.get("fingerprint") or C.fingerprint(
            f["rule_id"], str(loc.get("file", "")), ev["sanitized_code"] or f["title"])
        f["id"] = "SCR-0000"
        f["remediation_priority"] = C.remediation_priority(f["severity"], f["confidence"], f["status"])
        errs = C.validate_finding(f, where)
        if errs:
            raise InputError("\n".join(errs))
        out.append(f)
    return out


def merge_scans(docs: List[Dict[str, Any]]) -> Dict[str, Any]:
    base = docs[0]
    modes = {d["scan"]["mode"] for d in docs}
    scan = dict(base["scan"])
    scan["mode"] = modes.pop() if len(modes) == 1 else "mixed"
    if len(docs) > 1:
        scan["files_scanned"] = max(d["scan"]["files_scanned"] for d in docs)
        scan["files_skipped"] = max(d["scan"]["files_skipped"] for d in docs)
        scan["merged_inputs"] = len(docs)
    coverage: Dict[str, Dict[str, Any]] = {}
    for d in docs:
        for c in d["coverage"]:
            prev = coverage.get(c["category"])
            if prev is None or COVERAGE_ORDER[c["status"]] < COVERAGE_ORDER[prev["status"]]:
                coverage[c["category"]] = c
    deps: Dict[Tuple[str, str, Optional[str]], Dict[str, Any]] = {}
    for d in docs:
        for dep in d["dependencies"]:
            key = (dep["name"], dep["manifest"], dep.get("version"))
            if key not in deps or dep["vulnerability_status"] != "Not Verified":
                deps[key] = dep
    pending: List[str] = []
    for d in docs:
        for p in d["pending_verifications"]:
            if p not in pending:
                pending.append(p)
    return {
        "scan": scan,
        "inventory": base.get("inventory"),
        "coverage": list(coverage.values()),
        "pending_verifications": pending,
        "tool_errors": [e for d in docs for e in d["tool_errors"]],
        "dependencies": list(deps.values()),
        "findings": [dict(f) for d in docs for f in d["findings"]],
    }


def correlate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop exact duplicates and merge findings at the same file/line/CWE."""
    by_fp: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        by_fp.setdefault(f["fingerprint"], f)
    groups: Dict[Tuple[str, int, str], List[Dict[str, Any]]] = {}
    for f in by_fp.values():
        key = (f["location"]["file"], f["location"]["start_line"], f["cwe"])
        groups.setdefault(key, []).append(f)
    merged: List[Dict[str, Any]] = []
    for group in groups.values():
        group.sort(key=lambda f: (C.SEVERITY_RANK[f["severity"]], C.CONFIDENCE_RANK[f["confidence"]],
                                  0 if f["source"] in ("agent", "manual") else 1, f["fingerprint"]))
        primary = dict(group[0])
        if len(group) > 1:
            others = group[1:]
            primary["related_rules"] = sorted({o["rule_id"] for o in others})
            primary["merged_fingerprints"] = sorted(o["fingerprint"] for o in others)
            primary["sources"] = sorted({primary["source"], *(o["source"] for o in others)})
            best_conf = min([primary["confidence"]] + [o["confidence"] for o in others], key=C.CONFIDENCE_RANK.get)
            if len({primary["source"], *(o["source"] for o in others)}) > 1:
                # independent sources agreeing raise confidence by one level
                best_conf = C.CONFIDENCES[max(C.CONFIDENCE_RANK[best_conf] - 1, 0)]
            primary["confidence"] = best_conf
        merged.append(primary)
    return merged


def apply_triage(findings: List[Dict[str, Any]], path: str, pending: List[str]) -> None:
    data = C.load_json_file(path)
    entries = data.get("triage") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise InputError(f"{path}: expected a list or an object with 'triage'")
    for i, e in enumerate(entries):
        where = f"{path}[{i}]"
        if not isinstance(e, dict):
            raise InputError(f"{where}: entry must be an object")
        justification = str(e.get("justification", "")).strip()
        if len(justification) < 10:
            raise InputError(f"{where}: a justification (>= 10 chars) is required for every triage decision")
        for key, allowed in (("status", C.STATUSES), ("severity", C.SEVERITIES), ("confidence", C.CONFIDENCES)):
            if key in e and e[key] not in allowed:
                raise InputError(f"{where}: invalid {key} '{e[key]}'")
        matches = [f for f in findings if _triage_matches(e, f)]
        if not matches:
            pending.append(f"Triage entry #{i} in {Path(path).name} matched no finding; re-check it.")
            continue
        for f in matches:
            f["triage"] = {
                "original_severity": f["severity"], "original_status": f["status"],
                "original_confidence": f["confidence"], "justification": C.sanitize_text(justification, 1000),
                "reviewer": C.sanitize_text(str(e.get("reviewer", "unspecified")), 120),
            }
            for key in ("status", "severity", "confidence"):
                if key in e:
                    f[key] = e[key]
            if e.get("reproduced") is True:
                f.setdefault("verification", {})["reproduced"] = True


def _triage_matches(e: Dict[str, Any], f: Dict[str, Any]) -> bool:
    if "fingerprint" in e:
        return e["fingerprint"] == f["fingerprint"] or e["fingerprint"] in f.get("merged_fingerprints", [])
    if "rule_id" in e and "file" in e:
        return (f["rule_id"] == e["rule_id"] or e["rule_id"] in f.get("related_rules", [])) and \
            f["location"]["file"] == e["file"] and ("line" not in e or f["location"]["start_line"] == e["line"])
    if "id" in e:
        return f.get("input_id") == e["id"]
    return False


def build(args: argparse.Namespace) -> Dict[str, Any]:
    if not args.inputs and not args.add:
        raise InputError("provide at least one scan document or --add file")
    docs = [load_scan(p) for p in args.inputs]
    if docs:
        merged = merge_scans(docs)
    else:
        merged = {"scan": {"target": "manual", "mode": "full", "files_scanned": 0, "files_skipped": 0},
                  "inventory": None, "coverage": [], "pending_verifications": [], "tool_errors": [],
                  "dependencies": [], "findings": []}
    findings = merged["findings"]
    for f in findings:
        f["input_id"] = f["id"]
    for path in args.add or []:
        findings.extend(load_agent_findings(path))
        for entry in load_agent_coverage(path):
            # an explicit human/agent review replaces the scanner's entry for that category
            merged["coverage"] = [c for c in merged["coverage"] if c["category"] != entry["category"]] + [entry]
    findings = correlate(findings)
    pending = merged["pending_verifications"]
    for path in args.triage or []:
        apply_triage(findings, path, pending)
    baseline_map: Dict[str, str] = {}
    baseline_info: Optional[Dict[str, Any]] = None
    if args.baseline:
        base_doc = load_scan(args.baseline)
        for bf in base_doc["findings"]:
            baseline_map[bf["fingerprint"]] = bf["id"]
            for mfp in bf.get("merged_fingerprints", []):
                baseline_map.setdefault(mfp, bf["id"])
    # a finding keeps its baseline id if its primary or any merged fingerprint was known
    for f in findings:
        known = [baseline_map[fp] for fp in [f["fingerprint"], *f.get("merged_fingerprints", [])] if fp in baseline_map]
        f["_baseline_id"] = known[0] if known else None
    if not args.baseline:
        C.assign_ids(findings)
    else:
        # Reuse baseline ids (matched by primary or merged fingerprint); new findings get numbers
        # above every id ever used in the baseline, so ids are never recycled.
        used = set(baseline_map.values())
        next_num = 1 + max((int(i.split("-")[1]) for i in used), default=0)
        for f in sorted(findings, key=C.finding_sort_key):
            if f["_baseline_id"]:
                f["id"] = f["_baseline_id"]
                f["baseline_status"] = "existing"
            else:
                f["id"] = f"SCR-{next_num:04d}"
                next_num += 1
                f["baseline_status"] = "new"
        present = {f["id"] for f in findings}
        resolved = sorted({i for i in used if i not in present})
        baseline_info = {"compared": True, "new": sum(f["baseline_status"] == "new" for f in findings),
                         "existing": sum(f["baseline_status"] == "existing" for f in findings), "resolved_ids": resolved}
    for f in findings:
        f.pop("_baseline_id", None)
        f.pop("input_id", None)
        f["remediation_priority"] = C.remediation_priority(f["severity"], f["confidence"], f["status"])
    findings.sort(key=lambda f: (C.PRIORITIES.index(f["remediation_priority"]), C.finding_sort_key(f)))
    doc: Dict[str, Any] = {
        "schema_version": C.SCHEMA_VERSION,
        "tool": {"name": C.TOOL_NAME, "version": C.TOOL_VERSION, "component": "normalize_findings"},
        "generated_at": C.utc_now(),
        "stage": "normalized",
        "scan": merged["scan"],
    }
    if merged.get("inventory"):
        doc["inventory"] = merged["inventory"]
    doc.update({
        "coverage": merged["coverage"],
        "pending_verifications": pending,
        "tool_errors": merged["tool_errors"],
        "dependencies": merged["dependencies"],
        "findings": findings,
        "summary": C.summarize(findings),
    })
    if baseline_info:
        doc["baseline"] = baseline_info
    errors = C.validate_document(doc)
    if errors:
        raise InputError("normalized document failed validation:\n  " + "\n  ".join(errors[:20]))
    return doc


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Normalize, correlate and triage Secure Code Reviewer findings.")
    ap.add_argument("inputs", nargs="*", help="scan documents produced by scan_repository.py")
    ap.add_argument("--add", action="append", help="JSON file with agent/manual findings (repeatable)")
    ap.add_argument("--triage", action="append", help="JSON file with triage decisions (repeatable)")
    ap.add_argument("--baseline", help="previous normalized report to keep ids stable and detect new findings")
    ap.add_argument("--output", "-o", help="output path (default: stdout)")
    args = ap.parse_args(argv)
    try:
        doc = build(args)
        C.write_output(C.dump_json(doc), args.output)
    except (InputError, FileNotFoundError, ValueError, OSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    s = doc["summary"]
    sys.stderr.write(f"{s['total']} findings ({s['active']} active)"
                     + (f"; baseline: {doc['baseline']['new']} new, {len(doc['baseline']['resolved_ids'])} resolved"
                        if "baseline" in doc else "") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
