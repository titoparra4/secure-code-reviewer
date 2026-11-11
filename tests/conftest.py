"""Shared fixtures. Test secrets are assembled at runtime from fragments so that no complete
credential-shaped string exists in the repository (avoids push-protection noise and leaks)."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "secure-code-reviewer"  # the installable skill package
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))

import scan_repository  # noqa: E402
import scr_common  # noqa: E402

SCHEMA = json.loads((SKILL / "schemas" / "findings.schema.json").read_text(encoding="utf-8"))


def fake_secret(kind: str) -> str:
    """Fictitious, syntactically plausible secrets for tests only."""
    body = "Zq7" + "Lm2" + "Xw9" + "Pr4" + "Tn8" + "Kd3" + "Hv6" + "Bj1" + "Fy5" + "Gc0" + "Qs7" + "Wu2"
    if kind == "github":
        return "gh" + "p_" + body[:36]
    if kind == "aws-id":
        return "AK" + "IA" + "QZ7RT4NW2PXK9MLB"
    if kind == "stripe":
        return "sk" + "_live_" + body[:28]
    if kind == "generic":
        return body[:26]
    if kind == "password":
        return "Tr0ub4" + "dor-Prod-91"
    raise ValueError(kind)


@pytest.fixture
def make_repo(tmp_path: Path):
    def _make(files: Dict[str, str]) -> Path:
        root = tmp_path / "repo"
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        root.mkdir(exist_ok=True)
        return root
    return _make


def run_scan(target: Path, *extra: str) -> Dict[str, Any]:
    args = scan_repository.parse_args([str(target), *extra])
    doc = scan_repository.build_document(args)
    assert scr_common.validate_document(doc) == [], scr_common.validate_document(doc)
    return doc


def rule_ids(doc: Dict[str, Any]) -> List[str]:
    return [f["rule_id"] for f in doc["findings"]]


@pytest.fixture
def scan():
    return run_scan


@pytest.fixture
def schema():
    return SCHEMA
