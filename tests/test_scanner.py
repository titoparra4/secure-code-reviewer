"""Detection accuracy: vulnerable cases must be found, safe counterparts must not.

NOTE: dangerous-looking calls in this file (os.system, eval, pickle.loads, ...) are inert string
fixtures written to temporary files and scanned as text. They are never executed.
"""
from __future__ import annotations

import json

import pytest

from conftest import ROOT, rule_ids, run_scan

import dependency_parsers


# ---------------------------------------------------------------- 1. SQL injection

@pytest.mark.parametrize("filename,code", [
    ("a.py", "cur.execute(f\"SELECT * FROM users WHERE email = '{email}'\")\n"),
    ("b.py", "cur.execute(\"SELECT * FROM users WHERE id = \" + user_id)\n"),
    ("c.py", "cur.execute(\"SELECT * FROM users WHERE id = %s\" % user_id)\n"),
    ("d.js", "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);\n"),
    ("e.cs", "var cmd = new SqlCommand($\"SELECT * FROM Users WHERE Name = '{name}'\", conn);\n"),
    ("f.php", "$r = mysqli_query($c, \"SELECT * FROM users WHERE id = \" . $_GET['id']);\n"),
    ("g.java", "stmt.executeQuery(\"DELETE FROM orders WHERE id = \" + orderId);\n"),
])
def test_sql_injection_detected(make_repo, filename, code):
    doc = run_scan(make_repo({filename: code}))
    hits = [f for f in doc["findings"] if f["rule_id"] == "injection.sql.string-built-query"]
    assert len(hits) == 1
    f = hits[0]
    assert f["severity"] == "High" and f["cwe"] == "CWE-89"
    assert f["status"] in ("Probable", "Needs Manual Review")  # never auto-Confirmed
    assert f["location"] == {"file": filename, "start_line": 1, "end_line": 1}


@pytest.mark.parametrize("code", [
    "cur.execute(\"SELECT * FROM users WHERE email = %s\", (email,))\n",
    "cur.execute(\"SELECT * FROM users WHERE email = ?\", [email])\n",
    "db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);\n",
    "log.info(f\"Selected {n} rows from cache\")\n",
    "# cur.execute(f\"SELECT * FROM t WHERE a = {x}\")  -- commented out\n",
])
def test_sql_injection_safe_patterns_not_flagged(make_repo, code):
    doc = run_scan(make_repo({"safe.py" if "db.query" not in code else "safe.js": code}))
    assert "injection.sql.string-built-query" not in rule_ids(doc)


def test_request_input_raises_sql_confidence(make_repo):
    code = "email = request.args.get('email')\ncur.execute(f\"SELECT * FROM u WHERE e = '{email}'\")\n"
    doc = run_scan(make_repo({"app.py": code}))
    f = next(f for f in doc["findings"] if f["rule_id"] == "injection.sql.string-built-query")
    assert f["confidence"] == "High"


# ---------------------------------------------------------------- 3. JWT validation

@pytest.mark.parametrize("filename,code,rule", [
    ("a.py", "claims = jwt.decode(token, options={\"verify_signature\": False})\n", "auth.jwt.signature-not-verified"),
    ("b.py", "claims = jwt.decode(token, key, algorithms=[\"none\"])\n", "auth.jwt.signature-not-verified"),
    ("c.cs", "ValidateIssuerSigningKey = false,\n", "auth.jwt.signature-not-verified"),
    ("d.cs", "ValidateLifetime = false,\n", "auth.jwt.claims-not-validated"),
    ("e.js", "jwt.verify(t, k, { ignoreExpiration: true });\n", "auth.jwt.claims-not-validated"),
    ("f.js", "const claims = jwt.decode(req.headers.authorization);\n", "auth.jwt.decode-without-verify-node"),
])
def test_insecure_jwt_validation_detected(make_repo, filename, code, rule):
    doc = run_scan(make_repo({filename: code}))
    assert rule in rule_ids(doc)


def test_secure_jwt_validation_not_flagged(make_repo):
    code = "claims = jwt.decode(token, PUBLIC_KEY, algorithms=[\"RS256\"], audience=\"api\", issuer=ISS)\n"
    doc = run_scan(make_repo({"auth.py": code}))
    assert not [r for r in rule_ids(doc) if r.startswith("auth.jwt")]


def test_node_jwt_decode_downgraded_when_verify_present(make_repo):
    code = "const c = jwt.decode(t); // header inspection\nconst v = jwt.verify(t, key, {algorithms:['RS256']});\n"
    doc = run_scan(make_repo({"a.js": code}))
    f = next(f for f in doc["findings"] if f["rule_id"] == "auth.jwt.decode-without-verify-node")
    assert f["confidence"] == "Low"


# ---------------------------------------------------------------- 4. Docker / Kubernetes privileges

def test_privileged_container_configs_detected(make_repo):
    repo = make_repo({
        "docker-compose.yml": "services:\n  web:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        "k8s/pod.yaml": "spec:\n  hostPID: true\n  containers:\n    - securityContext:\n        runAsUser: 0\n        capabilities:\n          add:\n            - SYS_ADMIN\n",
        "Dockerfile": "FROM ubuntu\nUSER root\nRUN wget -qO- https://get.example.com | bash\n",
    })
    ids = rule_ids(run_scan(repo))
    for expected in ["container.privileged", "container.docker-socket-mount", "container.host-namespaces",
                     "container.runs-as-root-k8s", "container.dangerous-capabilities", "container.docker.user-root",
                     "container.docker.unpinned-base-image", "supply-chain.remote-script-pipe"]:
        assert expected in ids, expected


def test_hardened_container_not_flagged(make_repo):
    repo = make_repo({
        "k8s/pod.yaml": "spec:\n  containers:\n    - securityContext:\n        runAsNonRoot: true\n        allowPrivilegeEscalation: false\n        capabilities:\n          drop:\n            - ALL\n",
        "Dockerfile": "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nUSER app\n",
    })
    assert [r for r in rule_ids(run_scan(repo)) if r.startswith("container.")] == []


def test_terraform_egress_open_is_not_flagged(make_repo):
    tf = 'resource "x" "y" {\n  egress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    doc = run_scan(make_repo({"main.tf": tf}))
    hits = [f for f in doc["findings"] if f["rule_id"] == "iac.network.open-to-world"]
    assert [f["location"]["start_line"] for f in hits] == [6]


def test_github_actions_script_injection_detected(make_repo):
    wf = "on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n"
    assert "cicd.gha.script-injection" in rule_ids(run_scan(make_repo({".github/workflows/a.yml": wf})))


def test_github_actions_env_is_safe(tmp_path):
    root = tmp_path / "r"
    (root / ".github/workflows").mkdir(parents=True)
    (root / ".github/workflows/a.yml").write_text(
        "on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - env:\n          TITLE: ${{ github.event.issue.title }}\n"
        "        run: echo \"$TITLE\"\n")
    assert "cicd.gha.script-injection" not in rule_ids(run_scan(root))


# ---------------------------------------------------------------- 5. dependencies with unknown status

def test_dependencies_offline_are_not_verified(make_repo):
    repo = make_repo({"requirements.txt": "flask==2.0.1\nrequests\n", "package.json": json.dumps(
        {"dependencies": {"express": "^4.17.1", "left-pad": "*"}})})
    doc = run_scan(repo, "--mode", "dependencies")
    assert {d["vulnerability_status"] for d in doc["dependencies"]} == {"Not Verified"}
    assert any("Not Verified" in p for p in doc["pending_verifications"])
    ids = rule_ids(doc)
    assert "dependencies.wildcard-version" in ids and "dependencies.not-pinned" in ids
    assert "dependencies.missing-lockfile" in ids
    assert not any(r == "dependencies.known-vulnerability" for r in ids)  # nothing invented offline


def test_lockfile_resolves_versions(make_repo):
    repo = make_repo({
        "package.json": json.dumps({"dependencies": {"express": "^4.17.1"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"node_modules/express": {"version": "4.18.2"}}}),
    })
    doc = run_scan(repo, "--mode", "dependencies")
    dep = doc["dependencies"][0]
    assert dep["version"] == "4.18.2" and dep["pinned"] is True
    assert "dependencies.not-pinned" not in rule_ids(doc)


def test_osv_results_are_used_verbatim(make_repo, monkeypatch):
    calls = []

    def fake_http(url, payload, timeout):
        calls.append(url)
        if url.endswith("querybatch"):
            return {"results": [{"vulns": [{"id": "GHSA-test-0001"}]}]}
        return {"id": "GHSA-test-0001", "summary": "Test advisory", "database_specific": {"severity": "HIGH"},
                "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}]}

    monkeypatch.setattr(dependency_parsers, "_http_json", fake_http)
    monkeypatch.setattr(dependency_parsers.query_osv, "__defaults__", (20.0, 200, fake_http))
    doc = run_scan(make_repo({"requirements.txt": "flask==2.0.1\n"}), "--mode", "dependencies", "--osv")
    dep = doc["dependencies"][0]
    assert dep["vulnerability_status"] == "Vulnerable"
    f = next(f for f in doc["findings"] if f["rule_id"] == "dependencies.known-vulnerability")
    assert f["severity"] == "High" and "GHSA-test-0001" in f["evidence"]["description"]
    assert "2.2.5" in f["remediation"]["recommendation"]
    assert f["status"] == "Probable"  # reachability not assessed
    assert len(calls) == 2


@pytest.mark.parametrize("parser,text,expected", [
    (dependency_parsers.parse_go_mod, "module x\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n", ("github.com/gin-gonic/gin", "v1.9.1")),
    (dependency_parsers.parse_cargo_toml, "[dependencies]\nserde = \"1.0\"\n", ("serde", None)),
    (dependency_parsers.parse_pom, "<project><dependencies><dependency><groupId>org.x</groupId><artifactId>y</artifactId><version>1.2.3</version></dependency></dependencies></project>", ("org.x:y", "1.2.3")),
    (dependency_parsers.parse_gradle, "dependencies {\n  implementation 'com.a:b:2.0.1'\n}\n", ("com.a:b", "2.0.1")),
    (dependency_parsers.parse_csproj, '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>', ("Newtonsoft.Json", "13.0.1")),
    (dependency_parsers.parse_pyproject, "[project]\ndependencies = [\"django>=4.2\"]\n", ("django", None)),
])
def test_manifest_parsers(parser, text, expected):
    deps = parser(text, "manifest")
    assert (deps[0]["name"], deps[0]["version"]) == expected


# ---------------------------------------------------------------- 6. false-positive prevention

def test_secure_demo_has_no_findings():
    doc = run_scan(ROOT / "examples" / "secure-demo")
    assert doc["findings"] == [], [(f["rule_id"], f["location"]) for f in doc["findings"]]


def test_vulnerable_demo_expected_findings():
    doc = run_scan(ROOT / "examples" / "vulnerable-demo")
    ids = set(rule_ids(doc))
    expected = {
        "injection.sql.string-built-query", "injection.command.python", "injection.command.node",
        "path-traversal.user-path", "ssrf.user-controlled-url", "deserialization.python",
        "auth.jwt.signature-not-verified", "crypto.weak-hash", "crypto.insecure-random", "config.debug-enabled",
        "xss.server-reflected", "mass-assignment.request-body-binding", "errors.stack-trace-in-response",
        "secrets.generic-secret-assignment", "secrets.connection-string-password", "container.privileged",
        "iac.storage.public-acl", "webserver.legacy-tls", "cicd.gha.script-injection",
    }
    assert expected <= ids, expected - ids
    # the parameterized query in find_user_safe must not be reported
    sql_lines = [f["location"]["start_line"] for f in doc["findings"] if f["rule_id"] == "injection.sql.string-built-query"]
    assert len(sql_lines) == 1
    # scanner never claims confirmation
    assert all(f["status"] != "Confirmed" for f in doc["findings"])


def test_non_security_patterns_not_flagged(make_repo):
    code = ("model.eval()\nresult = ast.literal_eval(text)\nm = /abc/.exec(s);\n"
            "password_field = \"password\"\ntoken_url = \"https://auth.example.com/token\"\n"
            "API_KEY = os.environ[\"API_KEY\"]\nsecret = \"${SECRET}\"\npassword = \"changeme-in-env\"\n")
    doc = run_scan(make_repo({"a.py": code}))
    assert doc["findings"] == [], [(f["rule_id"], f["location"]["start_line"]) for f in doc["findings"]]


def test_test_paths_lower_confidence(make_repo):
    code = "cur.execute(\"SELECT * FROM t WHERE id = \" + x)\n"
    doc = run_scan(make_repo({"src/a.py": code, "tests/test_a.py": code}))
    conf = {f["location"]["file"]: f["confidence"] for f in doc["findings"]}
    assert conf["src/a.py"] == "Medium" and conf["tests/test_a.py"] == "Low"


def test_modes_limit_rule_families(make_repo):
    repo = make_repo({"a.py": "cur.execute(\"SELECT * FROM t WHERE id = \" + x)\n",
                      "docker-compose.yml": "services:\n  a:\n    privileged: true\n"})
    assert rule_ids(run_scan(repo, "--mode", "secrets")) == []
    assert rule_ids(run_scan(repo, "--mode", "config")) == ["container.privileged"]
    assert "container.privileged" not in rule_ids(run_scan(repo, "--mode", "api"))


def test_pr_mode_scans_only_changed_files(make_repo, tmp_path):
    repo = make_repo({"a.py": "os.system(cmd)\n", "b.py": "os.system(cmd)\n"})
    changed = tmp_path / "changed.txt"
    changed.write_text("b.py\n../outside.py\n")
    doc = run_scan(repo, "--mode", "pr", "--changed-files-from", str(changed))
    assert {f["location"]["file"] for f in doc["findings"]} == {"b.py"}
    assert doc["scan"]["changed_files_only"] is True
    assert doc["scan"]["files_skipped_by_reason"].get("outside_target") == 1
