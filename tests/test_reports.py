"""Report rendering (Markdown / SARIF), escaping of untrusted content and the CI gate.

NOTE: dangerous-looking calls in this file (os.system, eval, pickle.loads, ...) are inert string
fixtures written to temporary files and scanned as text. They are never executed.
"""
from __future__ import annotations

import copy
import json
import re
from argparse import Namespace

import pytest

from conftest import ROOT, run_scan

import ci_gate
import generate_report as G
import normalize_findings as N
import scr_common as C

TEMPLATE = (ROOT / "assets" / "report-template.md").read_text(encoding="utf-8")
PLACEHOLDERS = re.findall(r"\{\{(\w+)\}\}", TEMPLATE)


@pytest.fixture(scope="module")
def normalized(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("rep")
    raw = tmp / "raw.json"
    raw.write_text(json.dumps(run_scan(ROOT / "examples" / "vulnerable-demo")))
    return N.build(Namespace(inputs=[str(raw)], add=[str(ROOT / "examples/agent-findings.json")],
                             triage=[str(ROOT / "examples/triage.json")], baseline=None, output=None))


def test_markdown_has_all_sections(normalized):
    md = G.render_markdown(normalized, TEMPLATE)
    for heading in ["## 1. Executive Summary", "## 2. Findings Summary", "## 3. Detailed Findings",
                    "## 4. Security Coverage", "## 5. Dependencies", "## 6. Remediation Roadmap",
                    "## 7. Limitations and Pending Verifications", "Appendix A"]:
        assert heading in md
    assert not re.search(r"\{\{(" + "|".join(PLACEHOLDERS) + r")\}\}", md)  # evidence may contain ${{ }} legitimately
    for f in normalized["findings"]:
        if f["status"] != "False Positive":
            assert f"### {f['id']} " in md
    assert "**Security test.**" in md and "**Regression test.**" in md
    assert "not a guarantee" in md


def test_false_positives_only_in_appendix(normalized):
    md = G.render_markdown(normalized, TEMPLATE)
    fp = next(f for f in normalized["findings"] if f["status"] == "False Positive")
    assert f"### {fp['id']} " not in md
    assert fp["id"] in md.split("Appendix A")[1]


def test_markdown_escapes_untrusted_content(normalized):
    doc = copy.deepcopy(normalized)
    f = next(f for f in doc["findings"] if f["status"] != "False Positive")
    f["title"] = "Evil | <script>alert(1)</script> ```"
    f["evidence"]["sanitized_code"] = "x = 1\n```\n# injected heading"
    md = G.render_markdown(doc, TEMPLATE)
    assert "<script>" not in md
    assert "Evil \\| &lt;script&gt;" in md
    assert "```\n# injected heading" not in md


def test_sarif_structure(normalized):
    sarif = G.render_sarif(normalized)
    assert G.validate_sarif(sarif) == []
    run = sarif["runs"][0]
    active = [f for f in normalized["findings"] if f["status"] != "False Positive"]
    assert len(run["results"]) == len(active)
    r0 = run["results"][0]
    assert r0["partialFingerprints"]["secureCodeReviewer/v1"]
    assert r0["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    for rule in run["tool"]["driver"]["rules"]:
        assert 0.0 <= float(rule["properties"]["security-severity"]) <= 10.0


def test_sarif_path_prefix(normalized):
    sarif = G.render_sarif(normalized, "examples/vulnerable-demo")
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("examples/vulnerable-demo/")


def test_cli_rejects_invalid_input(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"findings": "nope"}')
    assert G.main([str(bad)]) == 2


# ---------------------------------------------------------------- CI gate

@pytest.fixture
def report_file(normalized, tmp_path):
    p = tmp_path / "report.json"
    p.write_text(json.dumps(normalized))
    return str(p)


def test_gate_is_report_only_by_default(report_file, capsys):
    assert ci_gate.main(["--report", report_file]) == 0


def test_gate_fails_on_threshold(report_file, capsys):
    assert ci_gate.main(["--report", report_file, "--fail-on", "high"]) == 1
    out = capsys.readouterr().out
    assert "::error file=" in out
    assert "REDACTED" not in out and "postgresql://" not in out  # no evidence in logs


def test_gate_ignores_unverified_statuses_by_default(normalized, tmp_path):
    doc = copy.deepcopy(normalized)
    for f in doc["findings"]:
        f["status"] = "Needs Manual Review"
    doc["summary"] = C.summarize(doc["findings"])
    p = tmp_path / "r.json"
    p.write_text(json.dumps(doc))
    assert ci_gate.main(["--report", str(p), "--fail-on", "low"]) == 0
    assert ci_gate.main(["--report", str(p), "--fail-on", "low", "--statuses", "Needs Manual Review"]) == 1


def test_gate_only_new_against_baseline(report_file):
    assert ci_gate.main(["--report", report_file, "--fail-on", "low", "--only-new", "--baseline", report_file]) == 0
    assert ci_gate.main(["--report", report_file, "--only-new"]) == 2  # no baseline information


def test_gate_distinguishes_tool_errors(normalized, tmp_path):
    doc = copy.deepcopy(normalized)
    doc["tool_errors"] = [{"tool": "semgrep", "message": "exit code 2"}]
    p = tmp_path / "r.json"
    p.write_text(json.dumps(doc))
    assert ci_gate.main(["--report", str(p)]) == 0
    assert ci_gate.main(["--report", str(p), "--fail-on-tool-error"]) == 2


def test_gate_invalid_report_exit_2(tmp_path):
    p = tmp_path / "r.json"
    p.write_text("{not json")
    assert ci_gate.main(["--report", str(p)]) == 2
