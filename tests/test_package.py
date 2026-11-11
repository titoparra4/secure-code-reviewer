"""The installable skill package must stay self-contained and free of intentionally vulnerable fixtures."""
from __future__ import annotations

import shutil
from pathlib import Path

from conftest import ROOT, SKILL

import validate_skill as V


def test_skill_package_and_repo_are_valid():
    errors, warnings = V.validate(SKILL, ROOT)
    assert errors == [] and warnings == []


def test_vulnerable_demo_inside_skill_package_is_rejected(tmp_path: Path):
    pkg = tmp_path / "secure-code-reviewer"
    shutil.copytree(SKILL, pkg)
    shutil.copytree(ROOT / "examples" / "vulnerable-demo", pkg / "examples" / "vulnerable-demo")
    errors, _ = V.validate(pkg)
    assert any("vulnerable-demo must live in the repository" in e for e in errors)


def test_skill_package_contains_no_demo_apps():
    names = {p.name for p in SKILL.rglob("*")}
    assert not names & {"vulnerable-demo", "secure-demo", "sample-review.md", "docker-compose.yml", "Dockerfile"}
