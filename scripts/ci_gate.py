#!/usr/bin/env python3
"""Deterministic CI gate for Secure Code Reviewer reports.

Default policy is REPORT-ONLY (--fail-on none): unverified findings never block a merge unless
the team explicitly configures a threshold. Output lists only ids, titles, files and lines - no
evidence snippets - so CI logs cannot leak secrets.

Exit codes:
  0 = policy passed
  1 = policy violated (findings at/above threshold)
  2 = invalid input / tool error (distinct from vulnerabilities)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scr_common as C  # noqa: E402


def evaluate(doc: Dict[str, Any], fail_on: str, statuses: List[str], min_confidence: str, only_new: bool,
             baseline_fps: Optional[set] = None) -> List[Dict[str, Any]]:
    if fail_on == "none":
        return []
    threshold = C.SEVERITY_RANK[fail_on.capitalize() if fail_on != "informational" else "Informational"]
    blocking = []
    for f in doc["findings"]:
        if f["status"] not in statuses:
            continue
        if C.SEVERITY_RANK[f["severity"]] > threshold:
            continue
        if C.CONFIDENCE_RANK[f["confidence"]] > C.CONFIDENCE_RANK[min_confidence]:
            continue
        if only_new:
            if baseline_fps is not None:
                if f["fingerprint"] in baseline_fps or any(m in baseline_fps for m in f.get("merged_fingerprints", [])):
                    continue
            elif f.get("baseline_status") != "new":
                continue
        blocking.append(f)
    return blocking


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Fail a CI job based on a Secure Code Reviewer report.")
    ap.add_argument("--report", required=True, help="findings document (scan or normalized)")
    ap.add_argument("--fail-on", default="none", choices=["none", "critical", "high", "medium", "low", "informational"],
                    help="minimum severity that fails the job (default: none = report only)")
    ap.add_argument("--statuses", default="Confirmed,Probable",
                    help="comma-separated statuses that can block (default: Confirmed,Probable)")
    ap.add_argument("--min-confidence", default="Medium", choices=C.CONFIDENCES)
    ap.add_argument("--only-new", action="store_true", help="block only findings not present in the baseline")
    ap.add_argument("--baseline", help="baseline report (alternative to a report normalized with --baseline)")
    ap.add_argument("--fail-on-tool-error", action="store_true", help="exit 2 if the report contains tool errors")
    args = ap.parse_args(argv)
    try:
        doc = C.load_json_file(args.report)
        errors = C.validate_document(doc)
        if errors:
            raise ValueError("invalid report: " + "; ".join(errors[:5]))
        baseline_fps = None
        if args.baseline:
            base = C.load_json_file(args.baseline)
            if C.validate_document(base):
                raise ValueError("invalid baseline report")
            baseline_fps = {f["fingerprint"] for f in base["findings"]} | {
                m for f in base["findings"] for m in f.get("merged_fingerprints", [])}
        statuses = [s.strip() for s in args.statuses.split(",") if s.strip()]
        bad = [s for s in statuses if s not in C.STATUSES]
        if bad:
            raise ValueError(f"unknown statuses: {bad}")
    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"::error::secure-code-reviewer gate could not evaluate the report: {exc}")
        return 2
    if args.only_new and baseline_fps is None and "baseline" not in doc:
        print("::error::--only-new requires --baseline or a report normalized with --baseline")
        return 2
    if doc["tool_errors"]:
        for e in doc["tool_errors"]:
            print(f"::warning::tool error ({e.get('tool')}): {C.sanitize_text(e.get('message', ''), 200)}")
        if args.fail_on_tool_error:
            return 2
    blocking = evaluate(doc, args.fail_on, statuses, args.min_confidence, args.only_new, baseline_fps)
    s = doc["summary"]
    print(f"Secure Code Reviewer: {s['total']} findings ({s['active']} active). Policy: fail-on={args.fail_on}, "
          f"statuses={','.join(statuses)}, min-confidence={args.min_confidence}, only-new={args.only_new}.")
    for f in blocking:
        l = f["location"]
        print(f"::error file={l['file']},line={l['start_line']}::{f['id']} {f['severity']} "
              f"({f['confidence']}, {f['status']}): {C.sanitize_text(f['title'], 160)}")
    if blocking:
        print(f"Policy violated: {len(blocking)} blocking finding(s).")
        return 1
    print("Policy passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
