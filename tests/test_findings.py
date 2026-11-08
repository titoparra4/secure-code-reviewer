"""Schema validity, identifier stability, correlation, triage and baselines.

NOTE: dangerous-looking calls in this file (os.system, eval, pickle.loads, ...) are inert string
fixtures written to temporary files and scanned as text. They are never executed.
"""
from __future__ import annotations

import copy
import json
from argparse import Namespace

import pytest

from conftest import ROOT, run_scan

import normalize_findings as N
import scr_common as C

jsonschema = pytest.importorskip("jsonschema")


def write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def normalize(inputs, add=None, triage=None, baseline=None):
    return N.build(Namespace(inputs=inputs, add=add, triage=triage, baseline=baseline, output=None))


# ---------------------------------------------------------------- 8. schema

def test_scan_output_matches_json_schema(schema):
    doc = run_scan(ROOT / "examples" / "vulnerable-demo")
    jsonschema.validate(doc, schema)


def test_normalized_output_matches_json_schema(schema, tmp_path):
    raw = write(tmp_path, "raw.json", run_scan(ROOT / "examples" / "vulnerable-demo"))
    doc = normalize([raw], add=[str(ROOT / "examples/agent-findings.json")], triage=[str(ROOT / "examples/triage.json")])
    jsonschema.validate(doc, schema)
    assert doc["stage"] == "normalized"


def test_committed_sample_report_is_valid(schema):
    doc = json.loads((ROOT / "examples" / "sample-report.json").read_text(encoding="utf-8"))
    jsonschema.validate(doc, schema)
    assert C.validate_document(doc) == []


@pytest.mark.parametrize("mutate,needle", [
    (lambda f: f.update(severity="Severe"), "invalid severity"),
    (lambda f: f.update(id="X-1"), "SCR-NNNN"),
    (lambda f: f["location"].update(file="../etc/passwd"), "relative path"),
    (lambda f: f["location"].update(start_line=0), "start_line"),
    (lambda f: f.update(cwe="89"), "cwe"),
    (lambda f: f["evidence"].update(sanitized_code="key = \"" + "gh" + "p_" + "a1B2" * 9 + "\""), "unredacted secret"),
])
def test_validator_rejects_invalid_findings(mutate, needle, schema):
    doc = json.loads((ROOT / "examples" / "sample-report.json").read_text(encoding="utf-8"))
    bad = copy.deepcopy(doc)
    mutate(bad["findings"][0])
    errors = C.validate_document(bad)
    assert any(needle in e for e in errors), errors


# ---------------------------------------------------------------- 9. id stability

def test_ids_stable_across_reruns():
    a = run_scan(ROOT / "examples" / "vulnerable-demo")
    b = run_scan(ROOT / "examples" / "vulnerable-demo")
    assert [(f["id"], f["fingerprint"]) for f in a["findings"]] == [(f["id"], f["fingerprint"]) for f in b["findings"]]


def test_fingerprint_independent_of_line_number(make_repo):
    code = "os.system(cmd)\n"
    a = run_scan(make_repo({"a.py": code}))
    b_root = make_repo({"a.py": "\n\n# unrelated edit\n" + code})
    b = run_scan(b_root)
    assert a["findings"][0]["fingerprint"] == b["findings"][0]["fingerprint"]
    assert a["findings"][0]["location"]["start_line"] != b["findings"][0]["location"]["start_line"]


def test_duplicate_lines_get_distinct_fingerprints(make_repo):
    doc = run_scan(make_repo({"a.py": "os.system(cmd)\nos.system(cmd)\n"}))
    fps = [f["fingerprint"] for f in doc["findings"]]
    assert len(fps) == 2 and len(set(fps)) == 2


def test_baseline_keeps_ids_and_marks_new_and_resolved(make_repo, tmp_path):
    repo = make_repo({"a.py": "os.system(cmd)\npickle.loads(data)\n"})
    first = normalize([write(tmp_path, "s1.json", run_scan(repo))])
    base = write(tmp_path, "base.json", first)
    old_ids = {f["rule_id"]: f["id"] for f in first["findings"]}
    # remove one issue, add a new one that would sort first
    (repo / "a.py").write_text("eval(user_code)\nos.system(cmd)\n")
    second = normalize([write(tmp_path, "s2.json", run_scan(repo))], baseline=base)
    new_ids = {f["rule_id"]: f for f in second["findings"]}
    assert new_ids["injection.command.python"]["id"] == old_ids["injection.command.python"]
    assert new_ids["injection.command.python"]["baseline_status"] == "existing"
    assert new_ids["injection.code.eval"]["baseline_status"] == "new"
    assert new_ids["injection.code.eval"]["id"] not in old_ids.values()  # ids never recycled
    assert second["baseline"]["resolved_ids"] == [old_ids["deserialization.python"]]


# ---------------------------------------------------------------- correlation / agent findings / triage

def test_agent_findings_are_added_and_sanitized(tmp_path):
    agent = json.loads((ROOT / "examples/agent-findings.json").read_text())
    agent["findings"][0]["evidence"]["sanitized_code"] = "token = \"" + "gh" + "p_" + "Q9w8" * 9 + "\""
    path = write(tmp_path, "agent.json", agent)
    doc = normalize([], add=[path])
    f = doc["findings"][0]
    assert f["source"] == "agent" and f["status"] == "Confirmed"
    assert "[REDACTED:github-token" in f["evidence"]["sanitized_code"]
    assert any(c["category"].startswith("Broken Access Control") and c["status"] == "reviewed" for c in doc["coverage"])


def test_agent_findings_missing_fields_rejected(tmp_path):
    path = write(tmp_path, "agent.json", {"findings": [{"title": "x"}]})
    with pytest.raises(N.InputError):
        normalize([], add=[path])


def test_correlation_merges_same_location_and_cwe(tmp_path):
    scan = run_scan(ROOT / "examples" / "vulnerable-demo")
    target = next(f for f in scan["findings"] if f["rule_id"] == "injection.command.python")
    dup = copy.deepcopy(target)
    dup.update(rule_id="semgrep.python.lang.security.audit.subprocess-shell-true", source="semgrep",
               fingerprint="f" * 32, confidence="Medium", id="SCR-9999")
    scan["findings"].append(dup)
    scan["summary"] = C.summarize(scan["findings"])
    doc = normalize([write(tmp_path, "s.json", scan)])
    merged = [f for f in doc["findings"] if f["location"] == target["location"] and f["cwe"] == "CWE-78"]
    assert len(merged) == 1
    assert merged[0]["related_rules"] == ["semgrep.python.lang.security.audit.subprocess-shell-true"]
    assert merged[0]["sources"] == ["scanner", "semgrep"]


def test_triage_requires_justification(tmp_path):
    raw = write(tmp_path, "raw.json", run_scan(ROOT / "examples" / "vulnerable-demo"))
    tri = write(tmp_path, "t.json", [{"rule_id": "crypto.weak-hash", "file": "app/app.py", "status": "False Positive"}])
    with pytest.raises(N.InputError, match="justification"):
        normalize([raw], triage=[tri])


def test_triage_preserves_original_values(tmp_path):
    raw = write(tmp_path, "raw.json", run_scan(ROOT / "examples" / "vulnerable-demo"))
    doc = normalize([raw], triage=[str(ROOT / "examples/triage.json")])
    fp = [f for f in doc["findings"] if f["status"] == "False Positive"]
    assert len(fp) == 1
    assert fp[0]["triage"]["original_status"] == "Needs Manual Review"
    assert fp[0]["remediation_priority"] == "P4"
    assert doc["summary"]["active"] == doc["summary"]["total"] - 1


def test_unmatched_triage_is_reported(tmp_path):
    raw = write(tmp_path, "raw.json", run_scan(ROOT / "examples" / "vulnerable-demo"))
    tri = write(tmp_path, "t.json", [{"fingerprint": "0" * 32, "status": "False Positive",
                                      "justification": "does not exist anywhere"}])
    doc = normalize([raw], triage=[tri])
    assert any("matched no finding" in p for p in doc["pending_verifications"])


@pytest.mark.parametrize("sev,conf,status,expected", [
    ("Critical", "High", "Confirmed", "P1"), ("High", "High", "Probable", "P1"), ("High", "Medium", "Probable", "P2"),
    ("Critical", "Low", "Needs Manual Review", "P2"), ("Medium", "High", "Probable", "P2"), ("Medium", "Low", "Probable", "P3"),
    ("Low", "High", "Confirmed", "P3"), ("Informational", "High", "Confirmed", "P4"), ("Critical", "High", "False Positive", "P4"),
])
def test_remediation_priority_matrix(sev, conf, status, expected):
    assert C.remediation_priority(sev, conf, status) == expected
