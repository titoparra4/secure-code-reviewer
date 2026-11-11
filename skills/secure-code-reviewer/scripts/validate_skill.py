#!/usr/bin/env python3
"""Validate the skill package structure (used in CI and before publishing).

Skill package checks (the folder that gets installed): SKILL.md frontmatter (name/description rules
of the Agent Skills format), referenced files exist, JSON files parse, the findings schema is in sync and
scripts compile. With --repo-root, also the repository around it: project files, sample reports are
valid and contain no unredacted secrets, tests compile, and workflows are least-privilege.
Nothing is executed.

Exit codes: 0 = valid, 1 = validation errors, 2 = usage error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scr_common as C  # noqa: E402

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
SKILL_FILES = [
    "SKILL.md", "LICENSE", "agents/openai.yaml", "schemas/findings.schema.json", "assets/report-template.md",
    "scripts/scan_repository.py", "scripts/normalize_findings.py", "scripts/generate_report.py",
    "scripts/validate_skill.py", "scripts/ci_gate.py", "examples/agent-findings.json", "examples/triage.json",
]
REPO_FILES = [
    "README.md", "LICENSE", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", ".gitignore",
    "examples/sample-report.json", "examples/sample-review.md", "examples/sample-report.sarif",
]
# Intentionally vulnerable fixtures must never ship inside the installed skill package.
FORBIDDEN_IN_SKILL = ["examples/vulnerable-demo", "examples/secure-demo", "examples/sample-review.md"]


def parse_frontmatter(text: str) -> Tuple[Optional[Dict[str, str]], str]:
    """Minimal YAML frontmatter parser for flat `key: value` pairs (with optional quotes/folded lines)."""
    if not text.startswith("---\n"):
        return None, "SKILL.md must start with a '---' YAML frontmatter block"
    end = text.find("\n---", 4)
    if end < 0:
        return None, "unterminated frontmatter"
    data: Dict[str, str] = {}
    key = None
    for raw in text[4:end].splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", raw)
        if m and not raw.startswith((" ", "\t")):
            key = m.group(1)
            value = m.group(2).strip()
            if value in (">", "|", ">-", "|-"):
                value = ""
            data[key] = value.strip("'\"") if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"" else value
        elif key and raw.startswith((" ", "\t")):
            data[key] = (data[key] + " " + raw.strip()).strip()
        else:
            return None, f"cannot parse frontmatter line: {raw[:60]}"
    return data, ""


def validate(root: Path, repo_root: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    for rel in SKILL_FILES:
        if not (root / rel).is_file():
            errors.append(f"missing required file: {rel}")
    for rel in FORBIDDEN_IN_SKILL:
        if (root / rel).exists():
            errors.append(f"{rel} must live in the repository, not in the installable skill package")
    skill = root / "SKILL.md"
    if skill.is_file():
        text = skill.read_text(encoding="utf-8")
        fm, err = parse_frontmatter(text)
        if fm is None:
            errors.append(err)
        else:
            allowed = {"name", "description", "license", "allowed-tools", "metadata", "compatibility"}
            for k in fm:
                if k not in allowed:
                    warnings.append(f"frontmatter key '{k}' is not part of the common Agent Skills fields")
            name = fm.get("name", "")
            desc = fm.get("description", "")
            if not NAME_RE.match(name) or len(name) > 64:
                errors.append("frontmatter 'name' must be lowercase kebab-case, <= 64 chars")
            if root.name != name:
                warnings.append(f"directory name '{root.name}' differs from skill name '{name}' "
                                "(install the skill into a folder named after it)")
            if not desc or len(desc) > 1024:
                errors.append("frontmatter 'description' must be 1-1024 characters")
            if "<" in desc or ">" in desc:
                errors.append("frontmatter 'description' must not contain angle brackets")
        lines = text.count("\n") + 1
        if lines > 500:
            warnings.append(f"SKILL.md has {lines} lines; keep it under 500 and move detail to references/")
        for ref in sorted(set(re.findall(r"`((?:references|scripts|schemas|assets|examples|agents)/[\w./-]+)`", text))):
            if not (root / ref).exists():
                errors.append(f"SKILL.md references missing file: {ref}")
    for jf in sorted(root.rglob("*.json")):
        if any(part in C.SKIP_DIRS for part in jf.relative_to(root).parts):
            continue
        try:
            json.loads(jf.read_text(encoding="utf-8"))
        except ValueError as exc:
            errors.append(f"invalid JSON in {jf.relative_to(root)}: {exc}")
    schema_path = root / "schemas/findings.schema.json"
    if schema_path.is_file():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        finding_props = set(schema["$defs"]["finding"]["required"])
        expected = {"id", "fingerprint", "rule_id", "title", "category", "severity", "confidence", "status", "cwe",
                    "owasp_category", "location", "evidence", "impact", "remediation", "source", "remediation_priority"}
        if finding_props != expected:
            errors.append("schema finding.required is out of sync with scr_common.validate_finding")
        if schema["properties"]["schema_version"].get("const") != C.SCHEMA_VERSION:
            errors.append("schema_version const differs from scr_common.SCHEMA_VERSION")
    for py in sorted((root / "scripts").glob("*.py")):
        errors.extend(_compile_error(py, root))
    openai = root / "agents/openai.yaml"
    if openai.is_file():
        content = openai.read_text(encoding="utf-8")
        for key in ("interface:", "display_name:", "short_description:"):
            if key not in content:
                errors.append(f"agents/openai.yaml missing '{key}'")
    if repo_root is not None:
        errors.extend(validate_repo(repo_root))
    return errors, warnings


def _compile_error(py: Path, base: Path) -> List[str]:
    try:
        compile(py.read_text(encoding="utf-8"), str(py), "exec")  # in memory: no .pyc written
    except SyntaxError as exc:
        return [f"{py.relative_to(base)} does not compile: line {exc.lineno}: {exc.msg}"]
    return []


def validate_repo(root: Path) -> List[str]:
    """Checks for the development repository that contains the skill (not shipped to users)."""
    errors: List[str] = []
    for rel in REPO_FILES:
        if not (root / rel).is_file():
            errors.append(f"missing repository file: {rel}")
    sample = root / "examples/sample-report.json"
    if sample.is_file():
        try:
            doc = json.loads(sample.read_text(encoding="utf-8"))
            for e in C.validate_document(doc):
                errors.append(f"examples/sample-report.json: {e}")
        except ValueError:
            pass
    for report in [root / "examples/sample-review.md", root / "examples/sample-report.json", root / "examples/sample-report.sarif"]:
        if report.is_file():
            content = report.read_text(encoding="utf-8")
            if C.redact_secrets(content) != content:
                errors.append(f"{report.relative_to(root)} contains an unredacted secret-like value")
    for py in sorted((root / "tests").glob("*.py")):
        errors.extend(_compile_error(py, root))
    for wf in sorted((root / ".github/workflows").glob("*.y*ml")) if (root / ".github/workflows").is_dir() else []:
        content = wf.read_text(encoding="utf-8")
        if not re.search(r"(?m)^permissions\s*:", content):
            errors.append(f"{wf.relative_to(root)} must declare top-level least-privilege permissions")
        if "write-all" in content or "pull_request_target" in content:
            errors.append(f"{wf.relative_to(root)} uses write-all or pull_request_target")
    return errors


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Validate the Secure Code Reviewer skill package.")
    ap.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--repo-root", help="also validate the development repository at this path")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    repo_root = Path(args.repo_root).resolve() if args.repo_root else None
    for d in (root, repo_root):
        if d is not None and not d.is_dir():
            print(f"error: not a directory: {d}", file=sys.stderr)
            return 2
    errors, warnings = validate(root, repo_root)
    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")
    if errors or (args.strict and warnings):
        print(f"validation failed: {len(errors)} error(s), {len(warnings)} warning(s)")
        return 1
    print(f"skill package valid ({len(warnings)} warning(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
