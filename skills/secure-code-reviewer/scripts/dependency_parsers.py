"""Offline dependency manifest/lockfile parsing and optional OSV lookups.

Parsing never executes package managers or build scripts. Network access happens only through
``query_osv`` and only when the caller explicitly enables it (``--osv``). Only package names,
versions and ecosystems are sent to OSV - never source code.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Tuple

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
MANIFEST_NAMES = {
    "requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "pyproject.toml", "poetry.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pom.xml", "build.gradle",
    "build.gradle.kts", "packages.lock.json", "go.mod", "cargo.toml", "cargo.lock",
}

Dep = Dict[str, Any]


def is_manifest(rel_path: str) -> bool:
    name = PurePosixPath(rel_path).name.lower()
    return name in MANIFEST_NAMES or name.endswith(".csproj") or (
        name.startswith("requirements") and name.endswith(".txt"))


def _dep(name: str, spec: str, ecosystem: str, manifest: str, line: int, version: Optional[str] = None,
         source: str = "registry") -> Dep:
    exact = version
    if exact is None and ecosystem == "PyPI":  # other parsers pass the exact version explicitly
        m = re.fullmatch(r"\s*(?:==|===)\s*v?(\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.\-+]+)?)\s*", spec or "")
        if m:
            exact = m.group(1)
    return {
        "name": name, "spec": spec, "version": exact, "ecosystem": ecosystem, "manifest": manifest,
        "line": line, "source": source, "pinned": exact is not None and source == "registry",
        "vulnerability_status": "Not Verified", "advisories": [],
    }


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


# --------------------------------------------------------------------------- parsers

def parse_requirements(text: str, manifest: str) -> List[Dep]:
    deps: List[Dep] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-r", "-c", "--")):
            continue
        if line.startswith("-e ") or re.match(r"^(git\+|https?://|file:)", line) or " @ " in line:
            name = re.split(r"[@#=\s]", line.replace("-e ", "").split("#egg=")[-1])[0] or line
            deps.append(_dep(name.strip(), line, "PyPI", manifest, i, source="url"))
            continue
        line = line.split(";")[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$", line)
        if m:
            deps.append(_dep(m.group(1), m.group(3).strip(), "PyPI", manifest, i))
    return deps


def parse_package_json(text: str, manifest: str) -> List[Dep]:
    data = json.loads(text)
    deps: List[Dep] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            source = "registry"
            if re.match(r"^(git\+|git:|github:|https?:|file:|link:|[\w-]+/[\w.-]+(#.*)?$)", spec):
                source = "url"
            exact = spec if re.fullmatch(r"\d+\.\d+\.\d+([-+][0-9A-Za-z.\-]+)?", spec) else None
            deps.append(_dep(name, spec, "npm", manifest, _line_of(text, f'"{name}"'), version=exact, source=source))
    return deps


def parse_package_lock(text: str) -> Dict[str, str]:
    data = json.loads(text)
    versions: Dict[str, str] = {}
    for key, meta in (data.get("packages") or {}).items():
        if key.startswith("node_modules/") and isinstance(meta, dict) and meta.get("version"):
            versions.setdefault(key.split("node_modules/")[-1], meta["version"])
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict) and meta.get("version"):
            versions.setdefault(name, meta["version"])
    return versions


def parse_yarn_lock(text: str) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    current: List[str] = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            current = []
            for spec in line.rstrip(":").split(","):
                spec = spec.strip().strip('"')
                name = spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else spec
                current.append(name)
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if m and current:
            for name in current:
                versions.setdefault(name, m.group(1))
            current = []
    return versions


def parse_pnpm_lock(text: str) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    for m in re.finditer(r"^\s{2}['\"]?/?((?:@[^/@\s]+/)?[^@\s/'\"]+)@(\d[^:(\s'\"]*)", text, re.M):
        versions.setdefault(m.group(1), m.group(2))
    return versions


def parse_pyproject(text: str, manifest: str) -> List[Dep]:
    deps: List[Dep] = []
    block = re.search(r"(?ms)^\s*dependencies\s*=\s*\[(.*?)\]", text)
    if block:
        for m in re.finditer(r"[\"']([^\"']+)[\"']", block.group(1)):
            req = m.group(1).split(";")[0].strip()
            n = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$", req)
            if n:
                deps.extend([_dep(n.group(1), n.group(3).strip(), "PyPI", manifest, _line_of(text, m.group(0)))])
    poetry = re.search(r"(?ms)^\[tool\.poetry(?:\.group\.\w+)?\.dependencies\]\s*$(.*?)(?=^\[|\Z)", text)
    if poetry:
        for m in re.finditer(r"(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+)$", poetry.group(1)):
            name, value = m.group(1), m.group(2).strip()
            if name.lower() == "python":
                continue
            source = "url" if re.search(r"\b(git|url|path)\s*=", value) else "registry"
            vm = re.search(r"version\s*=\s*[\"']([^\"']+)", value) or re.match(r"[\"']([^\"']+)", value)
            spec = vm.group(1) if vm else value
            exact = spec if re.fullmatch(r"\d+(\.\d+)*", spec) else None
            deps.append(_dep(name, spec, "PyPI", manifest, _line_of(text, m.group(0)), version=exact, source=source))
    return deps


def parse_toml_lock(text: str) -> Dict[str, str]:
    """poetry.lock and Cargo.lock share the [[package]] name/version layout."""
    versions: Dict[str, str] = {}
    for m in re.finditer(r'(?ms)^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text):
        versions.setdefault(m.group(1), m.group(2))
    return versions


def parse_cargo_toml(text: str, manifest: str) -> List[Dep]:
    deps: List[Dep] = []
    for sec in re.finditer(r"(?ms)^\[(?:dev-|build-)?dependencies\]\s*$(.*?)(?=^\[|\Z)", text):
        for m in re.finditer(r"(?m)^\s*([A-Za-z0-9_-]+)\s*=\s*(.+)$", sec.group(1)):
            value = m.group(2).strip()
            source = "url" if re.search(r"\b(git|path)\s*=", value) else "registry"
            vm = re.search(r"version\s*=\s*\"([^\"]+)\"", value) or re.match(r"\"([^\"]+)\"", value)
            spec = vm.group(1) if vm else value
            exact = spec.lstrip("=") if re.fullmatch(r"=\d+\.\d+\.\d+.*", spec) else None
            deps.append(_dep(m.group(1), spec, "crates.io", manifest, _line_of(text, m.group(0)), version=exact, source=source))
    return deps


def parse_go_mod(text: str, manifest: str) -> List[Dep]:
    deps: List[Dep] = []
    blocks = re.findall(r"(?ms)^require\s*\((.*?)^\)", text)
    lines = [ln for b in blocks for ln in b.splitlines()]
    lines += [m.group(1) for m in re.finditer(r"(?m)^require\s+([^\s(].*)$", text)]
    for ln in lines:
        m = re.match(r"^\s*(\S+)\s+(v\S+)", ln)
        if m:
            deps.append(_dep(m.group(1), m.group(2), "Go", manifest, _line_of(text, m.group(0).strip()),
                             version=m.group(2)))
    return deps


def parse_pom(text: str, manifest: str) -> List[Dep]:
    props = dict(re.findall(r"<([\w.\-]+)>([^<${}]+)</\1>",
                            (re.search(r"(?s)<properties>(.*?)</properties>", text) or [None, ""])[1] or ""))
    deps: List[Dep] = []
    for m in re.finditer(r"(?s)<dependency>(.*?)</dependency>", text):
        body = m.group(1)
        g = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", body)
        a = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", body)
        v = re.search(r"<version>\s*([^<]+?)\s*</version>", body)
        if not (g and a):
            continue
        spec = v.group(1) if v else ""
        pm = re.fullmatch(r"\$\{([^}]+)\}", spec)
        if pm and pm.group(1) in props:
            spec = props[pm.group(1)].strip()
        exact = spec if re.fullmatch(r"\d[\w.\-]*", spec) and not spec.startswith("[") else None
        deps.append(_dep(f"{g.group(1)}:{a.group(1)}", spec, "Maven", manifest, _line_of(text, m.group(0)), version=exact))
    return deps


def parse_gradle(text: str, manifest: str) -> List[Dep]:
    deps: List[Dep] = []
    pat = re.compile(r"(?m)^\s*(implementation|api|compile|runtimeOnly|testImplementation|compileOnly|kapt|annotationProcessor)"
                     r"\s*\(?\s*[\"']([^:\"']+):([^:\"']+):([^\"']+)[\"']")
    for m in pat.finditer(text):
        spec = m.group(4)
        exact = spec if re.fullmatch(r"\d[\w.\-]*", spec) else None
        deps.append(_dep(f"{m.group(2)}:{m.group(3)}", spec, "Maven", manifest, _line_of(text, m.group(0).strip()), version=exact))
    return deps


def parse_csproj(text: str, manifest: str) -> List[Dep]:
    deps: List[Dep] = []
    for m in re.finditer(r"<PackageReference\b([^>]*)/?>", text):
        attrs = dict(re.findall(r"(\w+)\s*=\s*\"([^\"]*)\"", m.group(1)))
        name = attrs.get("Include") or attrs.get("Update")
        if not name:
            continue
        spec = attrs.get("Version", "")
        exact = spec if re.fullmatch(r"\d+(\.\d+){1,3}([-+][\w.\-]+)?", spec) else None
        deps.append(_dep(name, spec, "NuGet", manifest, _line_of(text, m.group(0)), version=exact))
    return deps


def parse_packages_lock_json(text: str) -> Dict[str, str]:
    data = json.loads(text)
    versions: Dict[str, str] = {}
    for framework in (data.get("dependencies") or {}).values():
        for name, meta in (framework or {}).items():
            if isinstance(meta, dict) and meta.get("resolved"):
                versions.setdefault(name, meta["resolved"])
    return versions


MANIFEST_PARSERS: Dict[str, Callable[[str, str], List[Dep]]] = {
    "package.json": parse_package_json,
    "pyproject.toml": parse_pyproject,
    "cargo.toml": parse_cargo_toml,
    "go.mod": parse_go_mod,
    "pom.xml": parse_pom,
    "build.gradle": parse_gradle,
    "build.gradle.kts": parse_gradle,
}
LOCK_PARSERS: Dict[str, Tuple[str, Callable[[str], Dict[str, str]]]] = {
    "package-lock.json": ("npm", parse_package_lock),
    "yarn.lock": ("npm", parse_yarn_lock),
    "pnpm-lock.yaml": ("npm", parse_pnpm_lock),
    "poetry.lock": ("PyPI", parse_toml_lock),
    "cargo.lock": ("crates.io", parse_toml_lock),
    "packages.lock.json": ("NuGet", parse_packages_lock_json),
}


def collect_dependencies(files: List[Tuple[str, str]]) -> Tuple[List[Dep], List[Dict[str, str]], Dict[str, List[str]]]:
    """Parse (rel_path, text) manifest pairs.

    Returns (dependencies, parse_errors, lockfiles_by_dir).
    Lockfile versions resolve range specs from manifests in the same directory.
    """
    deps: List[Dep] = []
    errors: List[Dict[str, str]] = []
    locks: Dict[Tuple[str, str], Dict[str, str]] = {}
    lock_dirs: Dict[str, List[str]] = {}
    for rel, text in files:
        name = PurePosixPath(rel).name.lower()
        directory = str(PurePosixPath(rel).parent)
        try:
            if name in LOCK_PARSERS:
                eco, parser = LOCK_PARSERS[name]
                locks.setdefault((directory, eco), {}).update(parser(text))
                lock_dirs.setdefault(directory, []).append(PurePosixPath(rel).name)
            elif name in MANIFEST_PARSERS:
                deps.extend(MANIFEST_PARSERS[name](text, rel))
            elif name.startswith("requirements") and name.endswith(".txt"):
                deps.extend(parse_requirements(text, rel))
            elif name.endswith(".csproj"):
                deps.extend(parse_csproj(text, rel))
        except (ValueError, KeyError, TypeError) as exc:  # json errors are ValueError
            errors.append({"tool": "dependency-parser", "message": f"could not parse {rel}: {type(exc).__name__}"})
    for d in deps:
        directory = str(PurePosixPath(d["manifest"]).parent)
        resolved = locks.get((directory, d["ecosystem"]), {}).get(d["name"])
        if resolved and d["source"] == "registry":
            d["version"] = resolved
            d["pinned"] = True
            d["resolved_from"] = "lockfile"
    return deps, errors, lock_dirs


# --------------------------------------------------------------------------- OSV (opt-in network)

def _http_json(url: str, payload: Optional[Dict[str, Any]], timeout: float) -> Any:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json", "User-Agent": "secure-code-reviewer/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoint
        return json.loads(resp.read(10_000_000).decode("utf-8"))


SEVERITY_MAP = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}


def query_osv(deps: List[Dep], timeout: float = 20.0, max_details: int = 200,
              http: Callable[[str, Optional[Dict[str, Any]], float], Any] = _http_json) -> List[Dict[str, str]]:
    """Mutates ``deps`` with OSV results. Returns tool errors (never raises on network failure)."""
    errors: List[Dict[str, str]] = []
    queryable = [d for d in deps if d.get("version") and d["source"] == "registry"]
    for d in deps:
        if d not in queryable:
            d["verification_note"] = "version not pinned/resolved; cannot be checked against advisories"
    if not queryable:
        return errors
    details_budget = max_details
    for start in range(0, len(queryable), 1000):
        chunk = queryable[start:start + 1000]
        payload = {"queries": [{"package": {"name": d["name"], "ecosystem": d["ecosystem"]},
                                "version": d["version"].lstrip("v") if d["ecosystem"] != "Go" else d["version"]}
                               for d in chunk]}
        try:
            result = http(OSV_BATCH_URL, payload, timeout)
            results = result.get("results", [])
            if len(results) != len(chunk):
                raise ValueError("unexpected OSV response size")
        except (urllib.error.URLError, OSError, ValueError, AttributeError) as exc:
            errors.append({"tool": "osv", "message": f"OSV query failed: {type(exc).__name__}: {str(exc)[:200]}"})
            return errors
        for d, res in zip(chunk, results):
            vulns = (res or {}).get("vulns") or []
            if not vulns:
                d["vulnerability_status"] = "No Known Vulnerabilities"
                continue
            d["vulnerability_status"] = "Vulnerable"
            for v in vulns:
                adv: Dict[str, Any] = {"id": v.get("id", "unknown")}
                if details_budget > 0:
                    details_budget -= 1
                    try:
                        full = http(OSV_VULN_URL.format(id=urllib.request.quote(adv["id"])), None, timeout)
                        adv["summary"] = (full.get("summary") or "")[:300]
                        adv["aliases"] = [a for a in full.get("aliases", []) if isinstance(a, str)][:10]
                        sev = (full.get("database_specific") or {}).get("severity")
                        if isinstance(sev, str) and sev.upper() in SEVERITY_MAP:
                            adv["severity"] = SEVERITY_MAP[sev.upper()]
                        fixed = sorted({e["fixed"] for a in full.get("affected", []) for r in a.get("ranges", [])
                                        for e in r.get("events", []) if isinstance(e, dict) and "fixed" in e})
                        if fixed:
                            adv["fixed_versions"] = fixed[:10]
                    except (urllib.error.URLError, OSError, ValueError, AttributeError) as exc:
                        errors.append({"tool": "osv", "message": f"could not fetch {adv['id']}: {type(exc).__name__}"})
                d["advisories"].append(adv)
    return errors
