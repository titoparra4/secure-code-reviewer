"""Heuristic rule catalog for scan_repository.py.

IMPORTANT: every rule here is a *signal*, not proof. Rules are line/regex based with light
context (comment skipping, file-level mitigations, intra-file name-based taint tracking).
The scanner never emits status "Confirmed"; confirmation requires agent or human review.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------- file predicates

PY = {".py"}
JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
JAVA = {".java", ".kt", ".kts", ".scala", ".groovy"}
CS = {".cs", ".cshtml", ".razor"}
PHP = {".php", ".phtml"}
GO = {".go"}
RB = {".rb", ".erb"}
TEMPLATES = {".html", ".htm", ".jinja", ".jinja2", ".j2", ".ejs", ".hbs", ".njk", ".twig", ".erb", ".cshtml"}
CODE = PY | JS | JAVA | CS | PHP | GO | RB
TEXTUAL_CONFIG = {".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".xml",
                  ".tf", ".tfvars", ".hcl", ".sh", ".bash", ".zsh", ".ps1"}


def _suffix(p: str) -> str:
    return PurePosixPath(p).suffix.lower()


def _name(p: str) -> str:
    return PurePosixPath(p).name.lower()


def ext(*groups: Set[str]) -> Callable[[str], bool]:
    allowed: Set[str] = set().union(*groups)
    return lambda p: _suffix(p) in allowed


def is_dockerfile(p: str) -> bool:
    n = _name(p)
    return n.startswith("dockerfile") or n.endswith(".dockerfile") or n.startswith("containerfile")


def is_yaml(p: str) -> bool:
    return _suffix(p) in {".yml", ".yaml"}


def is_workflow(p: str) -> bool:
    return is_yaml(p) and "/.github/workflows/" in "/" + p.replace("\\", "/")


def is_ci_file(p: str) -> bool:
    n = _name(p)
    return is_workflow(p) or n in {".gitlab-ci.yml", "azure-pipelines.yml", "azure-pipelines.yaml",
                                   "jenkinsfile", "bitbucket-pipelines.yml"}


def is_terraform(p: str) -> bool:
    return _suffix(p) in {".tf", ".tfvars", ".hcl"} or p.lower().endswith(".tf.json")


def is_web_server_conf(p: str) -> bool:
    n = _name(p)
    return n == ".htaccess" or (n.endswith(".conf") and any(k in p.lower() for k in ("nginx", "httpd", "apache", "site"))) \
        or n in {"nginx.conf", "httpd.conf", "apache2.conf", "ssl.conf"}


def is_shellish(p: str) -> bool:
    return is_dockerfile(p) or is_ci_file(p) or _suffix(p) in {".sh", ".bash", ".zsh"} or _name(p) == "makefile"


def is_env_file(p: str) -> bool:
    n = _name(p)
    return (n == ".env" or n.startswith(".env.")) and not n.endswith((".example", ".sample", ".template", ".dist", ".tpl"))


def is_app_config(p: str) -> bool:
    n = _name(p)
    return is_env_file(p) or n in {"settings.py", "config.py", "application.properties", "application.yml",
                                   "application.yaml", "appsettings.json", "web.config"} or n.startswith("appsettings.")


def any_text(p: str) -> bool:
    return True


def code_or_config(p: str) -> bool:
    s = _suffix(p)
    return s in CODE or s in TEMPLATES or s in TEXTUAL_CONFIG or is_dockerfile(p) or is_env_file(p)


# --------------------------------------------------------------------------- user-input tracking

INPUT_RE = re.compile(
    r"request\.(args|form|values|files|json|data|cookies|headers|GET|POST|FILES|body|query_params|path_params|get_json)"
    r"|\breq\.(query|params|body|cookies|headers|files?)\b|\bctx\.(query|params|request\.body)"
    r"|getParameter\(|getHeader\(|Request\.(Query|Form|Headers|Cookies|RouteValues)"
    r"|\[From(Query|Body|Route|Form|Header)\]|\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"
    r"|r\.URL\.Query\(\)|r\.(Form|PostForm)Value\(|mux\.Vars\(|\bparams\[|location\.(hash|search|href)"
    r"|document\.(URL|location|referrer)|window\.name|(?<![\w.])input\("
)
ASSIGN_RE = re.compile(
    r"^\s*(?:(?:const|let|var|final|String|string|auto|my|val)\s+)?\$?([A-Za-z_]\w*)\s*"
    r"(?::\s*[\w\[\]<>, .|]+)?\s*(?::=|=)(?!=)\s*(.+)$"
)
DESTRUCT_RE = re.compile(r"^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)$")
ROUTE_RE = re.compile(r"@\w+(?:\.\w+)*\.(route|get|post|put|delete|patch|api_route)\(\s*[\"'][^\"']*[<{]")
DEF_PARAMS_RE = re.compile(r"^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)")
COMMON_NAMES = {"self", "cls", "request", "req", "res", "response", "db", "session", "app", "e", "err", "i", "_"}


def compute_tainted(lines: List[str]) -> Set[str]:
    """Approximate, name-based, intra-file taint: variables assigned (directly or transitively)
    from request input, plus Python route parameters. Not scope-aware; documented limitation."""
    tainted: Set[str] = set()
    pending_route = False
    for line in lines:
        if ROUTE_RE.search(line):
            pending_route = True
            continue
        if pending_route:
            m = DEF_PARAMS_RE.match(line)
            if m:
                for raw in m.group(1).split(","):
                    name = raw.split(":")[0].split("=")[0].strip().lstrip("*")
                    if name and name not in COMMON_NAMES and name.isidentifier():
                        tainted.add(name)
                pending_route = False
            elif line.strip() and not line.strip().startswith("@"):
                pending_route = False
        d = DESTRUCT_RE.match(line)
        if d and _rhs_tainted(d.group(2), tainted):
            for raw in d.group(1).split(","):
                name = raw.split(":")[-1].split("=")[0].strip()
                if name.isidentifier():
                    tainted.add(name)
            continue
        a = ASSIGN_RE.match(line)
        if a and a.group(1) not in COMMON_NAMES and _rhs_tainted(a.group(2), tainted):
            tainted.add(a.group(1))
    return tainted


def _rhs_tainted(rhs: str, tainted: Set[str]) -> bool:
    if INPUT_RE.search(rhs):
        return True
    return any(re.search(r"(?<![\w.])" + re.escape(t) + r"\b", rhs) for t in tainted)


@dataclass
class LineCtx:
    rel_path: str
    lines: List[str]
    index: int  # 0-based
    text: str
    tainted: Set[str]

    def has_input(self, line: str) -> bool:
        if INPUT_RE.search(line):
            return True
        return any(re.search(r"(?<![\w.])" + re.escape(t) + r"\b", line) for t in self.tainted)

    def window(self, before: int, after: int = 0) -> List[str]:
        return self.lines[max(0, self.index - before): self.index + after + 1]


# --------------------------------------------------------------------------- remediation profiles

P: Dict[str, Dict[str, str]] = {
    "sqli": dict(
        description="A SQL statement is built by string formatting/concatenation instead of bound parameters.",
        impact="If attacker-controlled data reaches the query, an attacker may read, modify or delete data, bypass authentication or, depending on the DBMS, execute commands.",
        conditions="Exploitable when any interpolated value is attacker-influenced and not strictly validated (e.g. integer cast or allow-list).",
        recommendation="Use parameterized queries / prepared statements or the ORM query builder. Never interpolate values into SQL; allow-list identifiers (column/table names) if they must be dynamic.",
        fixed_example="cursor.execute(\"SELECT * FROM users WHERE email = %s\", (email,))",
        security_test="Call the code path with a controlled payload such as `' OR '1'='1` against a local test database and assert that no extra rows are returned and no SQL error leaks.",
        regression_test="Unit test that asserts the query is executed with placeholders and a separate parameters tuple (mock the cursor) and that legitimate lookups still return the expected row.",
        verification="Run the regression test and the existing test suite; confirm the payload is treated as a literal value.",
        effort="Low"),
    "nosqli": dict(
        description="A NoSQL query receives a raw request object or uses server-side JavaScript evaluation.",
        impact="Operator injection (e.g. {\"$ne\": null}) can bypass filters or authentication checks.",
        conditions="Exploitable when request bodies are passed into query objects without type checks.",
        recommendation="Validate input types (strings, not objects), use schema validation and avoid $where / server-side JS.",
        fixed_example="const email = String(req.body.email); User.findOne({ email })",
        security_test="Send {\"email\": {\"$ne\": null}} to a local instance and assert the request is rejected.",
        regression_test="Test that object-typed inputs are rejected with 400 and valid strings still match.",
        verification="Run the tests; confirm that schema validation rejects operator objects.",
        effort="Low"),
    "cmdi": dict(
        description="An OS command is executed through a shell or with a dynamically built command string.",
        impact="Attacker-controlled data in the command can lead to arbitrary command execution with the application's privileges.",
        conditions="Exploitable when any part of the command string is attacker-influenced.",
        recommendation="Avoid the shell: pass an argument list (shell=False / execFile / ProcessBuilder with separate args), validate input against an allow-list and prefer native libraries over shelling out.",
        fixed_example="subprocess.run([\"ping\", \"-c\", \"1\", host], check=True, timeout=5)  # host validated against an allow-list/regex",
        security_test="In a sandbox, pass `127.0.0.1; id` and assert the command fails validation and `id` is never executed (mock subprocess).",
        regression_test="Assert subprocess is called with a list and shell=False, and that valid hosts still work.",
        verification="Run the tests; grep for remaining shell=True / exec( usages in the module.",
        effort="Medium"),
    "codei": dict(
        description="Dynamic code evaluation (eval/exec/new Function) is used.",
        impact="If input reaches the evaluated string, an attacker can execute arbitrary code in the application process.",
        conditions="Exploitable when the evaluated expression contains attacker-influenced data.",
        recommendation="Remove dynamic evaluation. Use a parser for the specific data format (json.loads, ast.literal_eval for Python literals) or an explicit dispatch table.",
        fixed_example="value = ast.literal_eval(text)  # or json.loads(text)",
        security_test="Pass `__import__('os').system('id')` (mocked) and assert it is rejected.",
        regression_test="Assert legitimate inputs are still parsed to the same values.",
        verification="Run the tests; confirm no eval/exec remains on the path.",
        effort="Medium"),
    "ssti": dict(
        description="A template is rendered from a string that may contain user input.",
        impact="Server-side template injection can lead to data disclosure or remote code execution.",
        conditions="Exploitable when user input becomes part of the template source (not just the context).",
        recommendation="Render fixed template files and pass user data only as context variables.",
        fixed_example="return render_template(\"hello.html\", name=name)",
        security_test="Send `{{7*7}}` and assert the response contains the literal text, not 49.",
        regression_test="Assert the page renders the escaped name.",
        verification="Run the tests and confirm autoescape is enabled.",
        effort="Low"),
    "deser": dict(
        description="Data is deserialized with a format/loader that can instantiate arbitrary objects.",
        impact="Deserializing attacker-controlled data can lead to remote code execution or object injection.",
        conditions="Exploitable when the serialized data can be influenced by an attacker (requests, cookies, queues, files, caches).",
        recommendation="Use data-only formats (JSON) or safe loaders (yaml.safe_load). If native serialization is unavoidable, sign/authenticate the payload and restrict allowed types.",
        fixed_example="data = yaml.safe_load(stream)",
        security_test="Feed a benign gadget payload (e.g. a YAML !!python/object tag) and assert it is rejected.",
        regression_test="Assert valid documents still load to the same structures.",
        verification="Run tests; confirm no unsafe loader remains.",
        effort="Medium"),
    "xxe": dict(
        description="An XML parser may resolve external entities or DTDs.",
        impact="XXE can disclose local files, perform SSRF or cause denial of service (entity expansion).",
        conditions="Exploitable when the parser processes attacker-supplied XML with DTD/entity resolution enabled.",
        recommendation="Disable DTDs and external entity resolution (e.g. disallow-doctype-decl, resolve_entities=False, DtdProcessing.Prohibit) or use a hardened parser such as defusedxml.",
        fixed_example="factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
        security_test="Parse a document with an external entity pointing to a local dummy file and assert parsing fails.",
        regression_test="Assert valid XML without DTD still parses.",
        verification="Run the tests; review all parser factory instantiations.",
        effort="Low"),
    "path": dict(
        description="A filesystem path is built from request input.",
        impact="Path traversal may allow reading or overwriting files outside the intended directory.",
        conditions="Exploitable when the input can contain `../`, absolute paths or encoded separators and no canonicalization check exists.",
        recommendation="Resolve the final path and verify it stays inside the base directory; prefer opaque identifiers mapped server-side; use safe helpers (send_from_directory, secure_filename).",
        fixed_example="target = (BASE_DIR / name).resolve()\nif not target.is_relative_to(BASE_DIR.resolve()):\n    abort(400)",
        security_test="Request `../../etc/passwd` and `..%2f..%2f` against a local instance and assert 400/404 without file contents.",
        regression_test="Assert valid file names inside the base directory are still served.",
        verification="Run tests; check every file access derived from user input.",
        effort="Low"),
    "upload": dict(
        description="An uploaded file is stored using the client-supplied filename.",
        impact="Attackers may overwrite files via path traversal or upload executable content.",
        conditions="Exploitable when the filename is not sanitized and the storage directory is reachable or executable.",
        recommendation="Generate server-side file names, sanitize with secure_filename, validate type by content, enforce size limits and store outside the web root.",
        fixed_example="name = f\"{uuid4().hex}{ext}\"  # ext from an allow-list\nfile.save(UPLOAD_DIR / name)",
        security_test="Upload a file named `../../evil.py` locally and assert it is stored under a generated name inside the upload dir.",
        regression_test="Assert a normal image upload still succeeds.",
        verification="Run tests; inspect the upload directory after the test.",
        effort="Medium"),
    "ssrf": dict(
        description="An outbound HTTP request uses a URL derived from user input.",
        impact="SSRF can reach internal services, cloud metadata endpoints or bypass network controls.",
        conditions="Exploitable when the attacker controls scheme/host and no allow-list or egress filtering exists.",
        recommendation="Allow-list destination hosts/schemes, resolve and block private/link-local ranges, disable redirects or re-validate them, and enforce egress controls.",
        fixed_example="if urlparse(url).hostname not in ALLOWED_HOSTS:\n    abort(400)",
        security_test="Request `http://169.254.169.254/` and `http://127.0.0.1:22` against a local instance (mock the HTTP client) and assert they are rejected.",
        regression_test="Assert allowed hosts are still fetched.",
        verification="Run tests; confirm redirects are validated too.",
        effort="Medium"),
    "redirect": dict(
        description="A redirect target is taken from user input.",
        impact="Open redirects enable phishing and can leak OAuth codes/tokens.",
        conditions="Exploitable when absolute URLs to arbitrary hosts are accepted.",
        recommendation="Only redirect to relative paths or allow-listed hosts.",
        fixed_example="if not url_is_safe(next_url, allowed_hosts={request.host}): next_url = '/'",
        security_test="Request `?next=https://attacker.example` and assert the redirect stays on-site.",
        regression_test="Assert relative redirects still work.",
        verification="Run tests.",
        effort="Low"),
    "xss": dict(
        description="Data is written into HTML without context-aware escaping, or escaping is explicitly disabled.",
        impact="Cross-site scripting allows session hijacking, account takeover actions and content spoofing in the victim's browser.",
        conditions="Exploitable when attacker-controlled data reaches the sink without encoding and no strict CSP mitigates it.",
        recommendation="Rely on framework auto-escaping, use textContent instead of innerHTML, sanitize rich HTML with a vetted sanitizer (e.g. DOMPurify) and deploy a strict Content-Security-Policy.",
        fixed_example="element.textContent = userValue;",
        security_test="Render `<img src=x onerror=alert(1)>` in a local test and assert it appears escaped in the output DOM/HTML.",
        regression_test="Assert normal text still renders identically.",
        verification="Run tests; check the response/DOM for escaped output.",
        effort="Low"),
    "csrf": dict(
        description="CSRF protection is disabled or exempted.",
        impact="State-changing requests may be forged from another origin using the victim's session.",
        conditions="Relevant when authentication relies on cookies (sessions). Token-only APIs (Authorization header) are generally not affected.",
        recommendation="Keep CSRF protection enabled for cookie-authenticated endpoints; use SameSite cookies and anti-CSRF tokens.",
        fixed_example="# remove @csrf_exempt and send the CSRF token from the client",
        security_test="Submit the state-changing request without a CSRF token in a local test and assert 403.",
        regression_test="Assert requests with a valid token still succeed.",
        verification="Run tests; confirm which authentication mechanism the endpoint uses.",
        effort="Low"),
    "massassign": dict(
        description="A model/object is created or updated directly from the request body.",
        impact="Attackers may set fields they should not control (e.g. is_admin, owner_id, balance).",
        conditions="Exploitable when the model has sensitive attributes and no allow-list/DTO restricts fields.",
        recommendation="Map input through an explicit allow-list or DTO/schema; never bind the raw body to persistence models.",
        fixed_example="data = UserUpdateSchema().load(request.json)  # only whitelisted fields\nuser.name = data['name']",
        security_test="Send `{\"is_admin\": true}` to the endpoint locally and assert the flag is not persisted.",
        regression_test="Assert allowed fields are still updated.",
        verification="Run tests; review the model for privileged attributes.",
        effort="Medium"),
    "proto": dict(
        description="A deep merge/extend uses attacker-controlled objects.",
        impact="Prototype pollution can alter application logic, bypass checks or lead to RCE via gadgets.",
        conditions="Exploitable when keys such as __proto__ or constructor.prototype are not filtered.",
        recommendation="Use safe merge utilities, reject __proto__/constructor/prototype keys, use Object.create(null) or Map, and validate input with a schema.",
        fixed_example="const safe = schema.parse(req.body); Object.assign(target, safe);",
        security_test="Send `{\"__proto__\": {\"polluted\": true}}` and assert `({}).polluted` is undefined afterwards.",
        regression_test="Assert normal merges still work.",
        verification="Run tests.",
        effort="Low"),
    "weakhash": dict(
        description="A weak hash algorithm (MD5/SHA-1) is used.",
        impact="If used for passwords, signatures or integrity, collisions or fast brute force undermine the control.",
        conditions="Only a vulnerability when the hash protects a security property; checksums/cache keys are usually acceptable.",
        recommendation="For passwords use Argon2id, scrypt or bcrypt with per-user salt; for integrity use SHA-256+ or HMAC.",
        fixed_example="from argon2 import PasswordHasher\nhash = PasswordHasher().hash(password)",
        security_test="Assert stored password hashes use the new algorithm prefix (e.g. $argon2id$).",
        regression_test="Assert login still works, including a migration path for legacy hashes.",
        verification="Run tests; confirm the purpose of each MD5/SHA-1 usage.",
        effort="Medium"),
    "weakcrypto": dict(
        description="A weak cipher or insecure block mode is used.",
        impact="ECB leaks plaintext patterns; DES/RC4 are breakable.",
        conditions="Relevant whenever the cipher protects confidential data.",
        recommendation="Use authenticated encryption (AES-GCM or ChaCha20-Poly1305) from a high-level library with random nonces.",
        fixed_example="from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
        security_test="Encrypt two identical blocks and assert ciphertext blocks differ.",
        regression_test="Assert round-trip encryption/decryption works.",
        verification="Run tests; plan migration of existing ciphertexts.",
        effort="High"),
    "prng": dict(
        description="A non-cryptographic PRNG appears to generate a security-sensitive value.",
        impact="Predictable tokens, passwords or OTPs can be guessed.",
        conditions="Relevant when the value is a secret, token, nonce, salt or identifier that must be unguessable.",
        recommendation="Use a CSPRNG: secrets.token_urlsafe (Python), crypto.randomBytes / crypto.randomUUID (Node), SecureRandom (Java), RandomNumberGenerator (.NET).",
        fixed_example="token = secrets.token_urlsafe(32)",
        security_test="Assert the token generator is backed by the CSPRNG (mock/inspect).",
        regression_test="Assert token length/format is unchanged.",
        verification="Run tests.",
        effort="Low"),
    "tls": dict(
        description="TLS certificate or hostname verification is disabled.",
        impact="Man-in-the-middle attackers can read or modify traffic, including credentials.",
        conditions="Exploitable by an attacker positioned on the network path.",
        recommendation="Keep verification enabled; trust a custom CA bundle explicitly if needed (verify='/path/ca.pem').",
        fixed_example="requests.get(url, timeout=10)  # verify defaults to True",
        security_test="Point the client at a local server with a self-signed cert and assert the connection fails.",
        regression_test="Assert normal HTTPS calls still succeed.",
        verification="Run tests.",
        effort="Low"),
    "jwt": dict(
        description="JWT validation is weakened (signature, algorithm or claim checks disabled).",
        impact="Attackers may forge or replay tokens, impersonating users or escalating privileges.",
        conditions="Exploitable when the token is used for authentication/authorization decisions.",
        recommendation="Always verify the signature with an explicit algorithm allow-list, and validate exp, nbf, iss and aud.",
        fixed_example="jwt.decode(token, key, algorithms=[\"RS256\"], audience=AUD, issuer=ISS)",
        security_test="Present a token signed with a different key and an `alg: none` token; assert both are rejected (401).",
        regression_test="Assert valid tokens are still accepted and expired tokens are rejected.",
        verification="Run tests covering signature, expiry, issuer and audience.",
        effort="Low"),
    "cookie": dict(
        description="A session or authentication cookie lacks Secure/HttpOnly protection.",
        impact="Cookies may be sent over plaintext HTTP or read by injected scripts.",
        conditions="Relevant for cookies carrying session or authentication state.",
        recommendation="Set Secure, HttpOnly and SameSite (Lax or Strict) on session cookies.",
        fixed_example="SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = 'Lax'",
        security_test="Assert the Set-Cookie header contains Secure; HttpOnly; SameSite.",
        regression_test="Assert login still sets the session cookie.",
        verification="Inspect response headers in tests.",
        effort="Low"),
    "plainpw": dict(
        description="A password appears to be compared directly, suggesting plaintext storage or non-constant-time comparison.",
        impact="Plaintext password storage exposes all credentials on a data breach.",
        conditions="Relevant if the compared value comes from storage.",
        recommendation="Store passwords with Argon2id/bcrypt/scrypt and verify with the library's verify function.",
        fixed_example="PasswordHasher().verify(user.password_hash, password)",
        security_test="Assert the stored value is a password hash, not the plaintext.",
        regression_test="Assert correct password succeeds and wrong password fails.",
        verification="Run tests and inspect the user table schema.",
        effort="Medium"),
    "debug": dict(
        description="Debug mode or developer error pages are enabled.",
        impact="Debug consoles and stack traces disclose internals and may allow code execution (e.g. Werkzeug debugger).",
        conditions="Relevant if this configuration reaches a deployed environment.",
        recommendation="Drive debug flags from environment configuration and default to off in production.",
        fixed_example="app.run(debug=os.environ.get('FLASK_DEBUG') == '1')",
        security_test="Assert production configuration loads with debug disabled.",
        regression_test="Assert the app still starts in development mode when explicitly enabled.",
        verification="Check deployment configuration.",
        effort="Low"),
    "cors": dict(
        description="CORS allows any origin.",
        impact="With credentials, any website could read authenticated responses.",
        conditions="Severe only when credentials (cookies) are allowed or the API serves non-public data.",
        recommendation="Allow-list trusted origins; never combine wildcard/reflected origins with credentials.",
        fixed_example="CORS(app, origins=[\"https://app.example.com\"], supports_credentials=True)",
        security_test="Send a request with Origin: https://evil.test and assert no ACAO header for it.",
        regression_test="Assert trusted origins still receive CORS headers.",
        verification="Run tests.",
        effort="Low"),
    "errors": dict(
        description="Exception details or stack traces are returned to the client.",
        impact="Internal paths, queries, versions or secrets may be disclosed and aid further attacks.",
        conditions="Relevant for responses reachable by untrusted users.",
        recommendation="Return generic error messages with a correlation id and log details server-side.",
        fixed_example="log.exception(\"failed\"); return jsonify(error=\"internal error\", id=req_id), 500",
        security_test="Trigger the error path and assert the body contains no stack trace.",
        regression_test="Assert error responses keep the expected status code.",
        verification="Run tests.",
        effort="Low"),
    "logging": dict(
        description="Sensitive values appear to be written to logs.",
        impact="Credentials or tokens in logs can be harvested by anyone with log access.",
        conditions="Relevant if the logged value is a real secret or credential.",
        recommendation="Never log secrets; mask values or log only non-sensitive identifiers.",
        fixed_example="log.info(\"login attempt for user_id=%s\", user_id)",
        security_test="Capture logs during the flow and assert the secret is absent.",
        regression_test="Assert the log entry still contains the useful context.",
        verification="Run tests with log capture.",
        effort="Low"),
    "tempfile": dict(
        description="Insecure temporary file creation (race-prone name generation).",
        impact="Race conditions (TOCTOU) may allow symlink attacks or file hijacking.",
        conditions="Relevant on shared/multi-user systems.",
        recommendation="Use tempfile.mkstemp/NamedTemporaryFile or TemporaryDirectory.",
        fixed_example="fd, path = tempfile.mkstemp()",
        security_test="N/A - code review; assert the secure API is used.",
        regression_test="Assert the temp file workflow still works.",
        verification="Run tests.",
        effort="Low"),
    "perms": dict(
        description="World-writable permissions are assigned.",
        impact="Other users/processes may modify files or binaries.",
        conditions="Relevant on shared hosts or containers with multiple processes.",
        recommendation="Grant the minimum permissions required (e.g. 0o600 / 0o640 / 0o750).",
        fixed_example="os.chmod(path, 0o600)",
        security_test="Assert resulting file mode in tests.",
        regression_test="Assert the owning process can still read/write.",
        verification="Run tests.",
        effort="Low"),
    "secret": dict(
        description="A credential-like value is hardcoded.",
        impact="Anyone with access to the source, history or build artifacts can use the credential.",
        conditions="Severity depends on whether the value is real, its privileges and where it is valid.",
        recommendation="Remove the value from source, load it from a secret manager or environment, and if it is (or may be) real: revoke/rotate it, review usage logs for abuse and purge it from git history.",
        fixed_example="API_KEY = os.environ[\"PAYMENTS_API_KEY\"]",
        security_test="Run a secrets scanner (this skill's secrets mode or gitleaks) in CI and assert zero unapproved findings.",
        regression_test="Assert the application reads the value from configuration and fails clearly when missing.",
        verification="Confirm rotation with the provider; re-run the secrets scan; check git history (e.g. `git log -S`).",
        effort="Medium"),
    "container": dict(
        description="The container/workload runs with elevated privileges or host access.",
        impact="A compromise of the container can escalate to the host or cluster.",
        conditions="Relevant if the workload is deployed with this configuration.",
        recommendation="Run as a non-root user, drop all capabilities, forbid privilege escalation, avoid host namespaces and the Docker socket, and enable a read-only root filesystem.",
        fixed_example="securityContext:\n  runAsNonRoot: true\n  allowPrivilegeEscalation: false\n  capabilities: { drop: [\"ALL\"] }",
        security_test="Use a policy check (e.g. Kubernetes Pod Security 'restricted' admission, or `docker inspect`) to assert the settings.",
        regression_test="Assert the service still starts and passes health checks as non-root.",
        verification="Deploy to a test cluster/namespace with restricted policy.",
        effort="Medium"),
    "image": dict(
        description="The base image is not pinned to a specific version/digest.",
        impact="Builds are not reproducible and may silently pull compromised or breaking images.",
        conditions="Supply-chain risk; exploitation requires a compromised or changed upstream image.",
        recommendation="Pin images to a version tag and preferably a digest (image@sha256:...), and update via automated PRs.",
        fixed_example="FROM python:3.12-slim@sha256:<digest>",
        security_test="Policy check in CI that rejects untagged/latest images.",
        regression_test="Rebuild and run the image test suite.",
        verification="Rebuild the image.",
        effort="Low"),
    "remote-script": dict(
        description="A remote script is downloaded and executed without integrity verification.",
        impact="A compromised server or MITM yields code execution in the build/runtime environment.",
        conditions="Exploitable if the remote source or transport is compromised.",
        recommendation="Download to a file, verify a pinned checksum or signature, then execute; prefer package managers.",
        fixed_example="curl -fsSLo install.sh URL && echo \"<sha256>  install.sh\" | sha256sum -c - && sh install.sh",
        security_test="CI check that rejects `| sh` patterns.",
        regression_test="Rebuild and confirm the tool installs.",
        verification="Rebuild.",
        effort="Low"),
    "iac-network": dict(
        description="A resource is exposed to the internet or allows unrestricted network access.",
        impact="Services become reachable by any attacker on the internet.",
        conditions="Relevant if the exposed port/service is not intended to be public.",
        recommendation="Restrict CIDR ranges to known networks, place services behind load balancers/WAF and use private subnets.",
        fixed_example="cidr_blocks = [var.office_cidr]",
        security_test="Run a policy check (e.g. checkov, tfsec/trivy config) in CI.",
        regression_test="Verify legitimate clients still connect from allowed ranges.",
        verification="Run `terraform plan` and review the security group diff.",
        effort="Low"),
    "iac-storage": dict(
        description="Storage or data service is publicly accessible or unencrypted.",
        impact="Data exposure or tampering.",
        conditions="Relevant for non-public data.",
        recommendation="Block public access, enable encryption at rest and in transit, and use least-privilege access policies.",
        fixed_example="acl = \"private\"\nblock_public_acls = true",
        security_test="Policy-as-code check in CI.",
        regression_test="Verify the application can still read/write with its role.",
        verification="Run `terraform plan`.",
        effort="Low"),
    "iam": dict(
        description="An access policy grants wildcard actions or principals.",
        impact="Excessive permissions enable privilege escalation and broad data access after any compromise.",
        conditions="Relevant whenever the policy is attached to a reachable identity/resource.",
        recommendation="Grant specific actions on specific resources; avoid Principal \"*\" except for intentionally public resources with conditions.",
        fixed_example="actions = [\"s3:GetObject\"]\nresources = [\"arn:aws:s3:::bucket/prefix/*\"]",
        security_test="Run IAM policy analysis (e.g. IAM Access Analyzer) or policy-as-code checks.",
        regression_test="Verify the workload still works with the reduced policy.",
        verification="Review CloudTrail/activity to confirm required permissions.",
        effort="Medium"),
    "tlsconf": dict(
        description="Legacy TLS/SSL protocol versions or weak ciphers are enabled.",
        impact="Downgrade and known protocol attacks weaken transport confidentiality.",
        conditions="Exploitable by network attackers against clients that negotiate the weak version.",
        recommendation="Allow only TLS 1.2 and 1.3 with modern cipher suites.",
        fixed_example="ssl_protocols TLSv1.2 TLSv1.3;",
        security_test="Run a TLS scanner (e.g. testssl.sh) against a local instance.",
        regression_test="Verify supported clients still connect.",
        verification="Reload the server and rescan.",
        effort="Low"),
    "webconf": dict(
        description="Web server configuration discloses information (directory listing, version banners).",
        impact="Helps attackers enumerate files and fingerprint versions.",
        conditions="Relevant for internet-facing servers.",
        recommendation="Disable directory listing and version banners.",
        fixed_example="autoindex off;\nserver_tokens off;",
        security_test="Request a directory without index locally and assert 403/404.",
        regression_test="Verify normal pages are still served.",
        verification="Reload and test.",
        effort="Low"),
    "cicd": dict(
        description="CI/CD workflow configuration allows untrusted input or excessive privileges.",
        impact="Attackers may execute code in CI, steal secrets or push malicious artifacts.",
        conditions="Exploitable via pull requests, issues or comments from untrusted users, depending on triggers.",
        recommendation="Use least-privilege `permissions:`, never interpolate untrusted event fields into `run:` (use env vars), avoid checking out PR code in pull_request_target, and pin actions to full commit SHAs.",
        fixed_example="env:\n  TITLE: ${{ github.event.pull_request.title }}\nrun: echo \"$TITLE\"",
        security_test="Review with actionlint/zizmor or equivalent workflow linters.",
        regression_test="Run the workflow on a test PR.",
        verification="Check the workflow run logs and permissions summary.",
        effort="Low"),
    "envfile": dict(
        description="An environment file is committed to the repository.",
        impact="Environment files typically hold credentials and configuration secrets.",
        conditions="Relevant if the file contains real values.",
        recommendation="Remove the file from version control, add it to .gitignore, commit a `.env.example` with placeholders, and rotate any real secrets.",
        fixed_example="echo '.env' >> .gitignore && git rm --cached .env",
        security_test="Secrets scan in CI.",
        regression_test="Verify the app loads configuration from the environment.",
        verification="Check git history for the file.",
        effort="Low"),
    "exposure": dict(
        description="Management/diagnostic endpoints are broadly exposed.",
        impact="Actuator-style endpoints may disclose environment, heap dumps or allow state changes.",
        conditions="Relevant if reachable by untrusted users.",
        recommendation="Expose only health/info and protect management endpoints with authentication and network controls.",
        fixed_example="management.endpoints.web.exposure.include=health,info",
        security_test="Request /actuator/env locally and assert 404/401.",
        regression_test="Assert /actuator/health still responds.",
        verification="Run tests.",
        effort="Low"),
    "prompt-injection": dict(
        description="Repository content contains text that tries to instruct AI reviewers or agents.",
        impact="Could manipulate AI-assisted reviews (e.g. suppress findings) or downstream LLM features.",
        conditions="Relevant to any AI-assisted workflow that reads this content.",
        recommendation="Treat as untrusted data; investigate who added it and why. If the app feeds this text to an LLM, isolate it from instructions.",
        fixed_example="(remove the embedded instruction)",
        security_test="N/A - manual review.",
        regression_test="N/A.",
        verification="Manual review of the surrounding content and its history.",
        effort="Low"),
}


# --------------------------------------------------------------------------- rule model

@dataclass
class Rule:
    id: str
    title: str
    category: str
    profile: str
    cwe: str
    owasp: str
    severity: str
    confidence: str
    applies: Callable[[str], bool]
    tags: Set[str]
    pattern: Optional["re.Pattern[str]"] = None
    status: str = "Probable"
    owasp_api: Optional[str] = None
    exclude: Optional["re.Pattern[str]"] = None
    mitigated_if: Optional["re.Pattern[str]"] = None  # file-level mitigation -> lower confidence
    needs_input: bool = False
    input_boost: bool = False
    matcher: Optional[Callable[[str, LineCtx], bool]] = None
    adjust: Optional[Callable[[str, LineCtx], Optional[Dict[str, Any]]]] = None
    skip_comments: bool = True
    file_check: Optional[Callable[[str, List[str]], Optional[Tuple[int, str]]]] = None
    references: List[str] = field(default_factory=list)


def rx(p: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(p, flags)


COMMENT_RE = re.compile(r"^\s*(#(?!!)|//|/\*|\*(?!\*?/)|<!--|--\s|;\s|')")

A01 = "A01:2021-Broken Access Control"
A02 = "A02:2021-Cryptographic Failures"
A03 = "A03:2021-Injection"
A04 = "A04:2021-Insecure Design"
A05 = "A05:2021-Security Misconfiguration"
A06 = "A06:2021-Vulnerable and Outdated Components"
A07 = "A07:2021-Identification and Authentication Failures"
A08 = "A08:2021-Software and Data Integrity Failures"
A09 = "A09:2021-Security Logging and Monitoring Failures"
A10 = "A10:2021-Server-Side Request Forgery"


# --------------------------------------------------------------------------- custom matchers

SQL_KW = rx(r"(?i)\b(select\b[^\n]*?\bfrom|insert\s+into|update\s+[\w.\"`\[\]]+\s+set|delete\s+from|"
            r"merge\s+into|exec(?:ute)?\s+sp_\w+)\b")
SQL_INTERP = [
    rx(r"""\bf"[^"]*\{|\bf'[^']*\{"""),              # python f-string
    rx(r"`[^`]*\$\{"),                              # JS template literal
    rx(r"\$@?\"[^\"]*\{"),                          # C# interpolated string
    rx(r"""["'`]\s*\+\s*[A-Za-z_$(\[]"""),          # "..." + var
    rx(r"""[A-Za-z_)\]]\s*\+\s*["'`]"""),           # var + "..."
    rx(r"""["']\s*%\s*[A-Za-z_(\[{]"""),            # "..." % var
    rx(r"""["']\s*\.format\("""),                   # "...".format(
    rx(r"""["']\s*\.\s*\$\w"""),                    # PHP "..." . $var
    rx(r"""\"[^\"]*\$[A-Za-z_]\w*"""),              # PHP "...$var..."
    rx(r"""fmt\.Sprintf\("""),                      # Go
    rx(r"""String\.format\(|string\.Format\("""),   # Java / C#
]


def sql_matcher(line: str, ctx: LineCtx) -> bool:
    if not SQL_KW.search(line):
        return False
    return any(p.search(line) for p in SQL_INTERP)


def sql_adjust(line: str, ctx: LineCtx) -> Optional[Dict[str, Any]]:
    if ctx.has_input(line):
        return {"confidence": "High", "note": "request-derived data appears on the same line"}
    return None


def literal_only_call(fn: str) -> "re.Pattern[str]":
    return rx(fn + r"\(\s*([\"'])[^\"'{}%+$`]*\1\s*\)")


def weakhash_adjust(line: str, ctx: LineCtx) -> Optional[Dict[str, Any]]:
    if re.search(r"usedforsecurity\s*=\s*False", line):
        return {"suppress": True}
    window = " ".join(ctx.window(2, 1))
    if re.search(r"(?i)passw|pwd", window):
        return {"severity": "High", "confidence": "High", "cwe": "CWE-916", "status": "Probable",
                "title": "Weak password hashing (fast, unsalted hash)",
                "note": "password-related identifiers near the hash call"}
    return None


SECURITY_VALUE = rx(r"(?i)token|secret|passw|otp|nonce|salt|session|api_?key|reset|csrf|verification|invite")


def prng_matcher(line: str, ctx: LineCtx) -> bool:
    return bool(SECURITY_VALUE.search(line))


def jsdecode_adjust(line: str, ctx: LineCtx) -> Optional[Dict[str, Any]]:
    if re.search(r"jwt\.verify\(", ctx.text):
        return {"confidence": "Low", "note": "jwt.verify is also used in this file; decode may be for non-auth purposes"}
    return None


def cors_adjust(line: str, ctx: LineCtx) -> Optional[Dict[str, Any]]:
    if re.search(r"(?i)credentials[\"']?\s*[:=]\s*true|Allow-Credentials[\"']?\s*[,:\s]\s*[\"']?true|"
                 r"supports_credentials\s*=\s*True|AllowCredentials\(\)", ctx.text):
        return {"severity": "Medium", "confidence": "Medium", "note": "credentials are also enabled in this file"}
    return None


def devpage_adjust(line: str, ctx: LineCtx) -> Optional[Dict[str, Any]]:
    if "IsDevelopment" in ctx.text:
        return {"severity": "Informational", "note": "appears gated by IsDevelopment()"}
    return None


def prt_adjust(line: str, ctx: LineCtx) -> Optional[Dict[str, Any]]:
    if re.search(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref", ctx.text):
        return {"severity": "High", "confidence": "High",
                "note": "pull_request_target workflow checks out or references the PR head"}
    return {"severity": "Low", "status": "Needs Manual Review"}


def cidr_adjust(line: str, ctx: LineCtx) -> Optional[Dict[str, Any]]:
    for prev in reversed(ctx.window(25)):
        m = re.search(r"\b(ingress|egress)\b", prev)
        if m:
            if m.group(1) == "egress":
                return {"suppress": True}
            return None
    if re.search(r"(?i)egress", line):
        return {"suppress": True}
    return {"severity": "Low", "confidence": "Low", "status": "Needs Manual Review"}


def caps_matcher(line: str, ctx: LineCtx) -> bool:
    if re.search(r"(cap_add|add)\s*:\s*\[[^\]]*\b(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE)\b", line):
        return True
    if not re.match(r"^\s*-\s*[\"']?(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE)[\"']?\s*$", line):
        return False
    for prev in reversed(ctx.window(6)[:-1]):
        key = re.match(r"^\s*([\w-]+)\s*:\s*$", prev)
        if key:
            return key.group(1) in ("cap_add", "add")
    return False


GHA_UNTRUSTED = rx(
    r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|discussion_comment|"
    r"head_commit|commits|pages|workflow_run)\b[^}]*\.(title|body|message|name|label|ref|email|head_branch|"
    r"default_branch)\b[^}]*|github\.head_ref)\s*\}\}")


def gha_injection_matcher(line: str, ctx: LineCtx) -> bool:
    if not GHA_UNTRUSTED.search(line):
        return False
    if re.match(r"^\s*(-\s*)?(if|name)\s*:", line):
        return False
    # Interpolation inside an env: mapping is the recommended mitigation.
    for prev in reversed(ctx.window(8)[:-1]):
        key = re.match(r"^\s*(-\s*)?([\w-]+)\s*:\s*(\||>)?\s*$", prev)
        if key:
            return key.group(2) not in ("env", "with")
    return True


def uses_unpinned_matcher(line: str, ctx: LineCtx) -> bool:
    m = re.match(r"^\s*-?\s*uses:\s*[\"']?([^@\s#\"']+)@([^\s#\"']+)", line)
    if not m:
        return False
    if m.group(1).startswith(("./", "docker://")):
        return False
    return not re.fullmatch(r"[0-9a-f]{40}", m.group(2))


TLS_LINE = rx(r"(?i)ssl_protocols|SSLProtocol|ssl-protocols|min_tls|tls_version|MinVersion")


def legacy_tls_matcher(line: str, ctx: LineCtx) -> bool:
    if not TLS_LINE.search(line):
        return False
    return bool(re.search(r"(?<![-\w!])\+?(SSLv2|SSLv3|TLSv1(?:\.1)?)(?![.\d\w])", line))


def env_file_check(rel_path: str, lines: List[str]) -> Optional[Tuple[int, str]]:
    meaningful = [ln for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    if not meaningful:
        return None
    first = next(i for i, ln in enumerate(lines) if ln.strip() and not ln.strip().startswith("#"))
    return first + 1, lines[first]


def docker_no_user_check(rel_path: str, lines: List[str]) -> Optional[Tuple[int, str]]:
    if any(re.match(r"^\s*USER\s+\S", ln, re.I) for ln in lines):
        return None
    for i, ln in enumerate(lines):
        if re.match(r"^\s*FROM\s", ln, re.I):
            return i + 1, ln
    return None


def gha_permissions_check(rel_path: str, lines: List[str]) -> Optional[Tuple[int, str]]:
    if any(re.match(r"^\s*permissions\s*:", ln) for ln in lines):
        return None
    for i, ln in enumerate(lines):
        if re.match(r"^on\s*:|^[\"']?on[\"']?\s*:", ln):
            return i + 1, ln
    return (1, lines[0]) if lines else None


# --------------------------------------------------------------------------- catalog

CODE_TAGS = {"code"}
AUTH_TAGS = {"auth"}
CFG_TAGS = {"config"}

RULES: List[Rule] = [
    # ---- injection
    Rule("injection.sql.string-built-query", "SQL query built with string interpolation", "SQL Injection", "sqli",
         "CWE-89", A03, "High", "Medium", ext(CODE), CODE_TAGS | {"api"}, matcher=sql_matcher, adjust=sql_adjust,
         owasp_api=None),
    Rule("injection.nosql.operator-or-where", "NoSQL query built from raw request object or $where", "NoSQL Injection",
         "nosqli", "CWE-943", A03, "Medium", "Medium", ext(JS, PY, PHP), CODE_TAGS | {"api"},
         pattern=rx(r"\$where\s*:|\.(find|findOne|find_one|update_one|updateOne|deleteMany|delete_many)\(\s*(req\.(body|query)|request\.(json|args|get_json\(\)))\s*\)")),
    Rule("injection.command.python", "OS command execution through a shell", "Command Injection", "cmdi",
         "CWE-78", A03, "High", "Medium", ext(PY), CODE_TAGS,
         pattern=rx(r"\bos\.(system|popen)\(|\bsubprocess\.\w+\([^\n]*shell\s*=\s*True|\bcommands\.getoutput\("),
         exclude=rx(r"\bos\.(system|popen)\(\s*([\"'])[^\"'{}%+]*\2\s*\)"), input_boost=True),
    Rule("injection.command.node", "child_process exec with a dynamic command", "Command Injection", "cmdi",
         "CWE-78", A03, "High", "Medium", ext(JS), CODE_TAGS,
         pattern=rx(r"(?:(?<![\w.])|child_process\.|cp\.)(exec|execSync)\(\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+|[A-Za-z_$][\w.$]*\s*[,)])"
                    r"|\bspawn\([^\n]*shell\s*:\s*true"),
         input_boost=True),
    Rule("injection.command.java-dotnet-php-go", "Process execution with a dynamic command", "Command Injection",
         "cmdi", "CWE-78", A03, "High", "Low", ext(JAVA, CS, PHP, GO, RB), CODE_TAGS,
         pattern=rx(r"Runtime\.getRuntime\(\)\.exec\(|Process\.Start\([^)]*\+|\b(system|shell_exec|passthru|popen|proc_open)\(\s*[^\"')]*\$"
                    r"|exec\.Command\(\s*\"(sh|bash|cmd(\.exe)?)\"\s*,\s*\"(-c|/c)\"|`[^`]*#\{"),
         status="Needs Manual Review", input_boost=True),
    Rule("injection.code.eval", "Dynamic code evaluation", "Code Injection", "codei", "CWE-95", A03, "High", "Medium",
         ext(PY, JS, PHP, RB), CODE_TAGS,
         pattern=rx(r"(?<![\w.])eval\(|\bnew\s+Function\(|\bsetTimeout\(\s*[\"'`]|\bsetInterval\(\s*[\"'`]"),
         exclude=rx(r"(?<![\w.])eval\(\s*([\"'])[^\"'{}%+$`]*\1\s*\)"), input_boost=True),
    Rule("injection.code.exec-python", "Dynamic code execution with exec()", "Code Injection", "codei", "CWE-95", A03,
         "High", "Medium", ext(PY), CODE_TAGS, pattern=rx(r"(?<![\w.])exec\("),
         exclude=rx(r"(?<![\w.])exec\(\s*([\"'])[^\"'{}%+]*\1\s*\)"), input_boost=True),
    Rule("injection.ssti.render-template-string", "Template rendered from a dynamic string", "Server-Side Template Injection",
         "ssti", "CWE-1336", A03, "High", "Medium", ext(PY), CODE_TAGS,
         pattern=rx(r"render_template_string\(|Template\(\s*(f[\"']|[A-Za-z_][\w.]*\s*[,)+])|Environment\([^)]*\)\.from_string\("),
         exclude=rx(r"render_template_string\(\s*([\"'])[^\"'{}%+]*\1\s*[,)]"), input_boost=True),
    # ---- deserialization / XXE
    Rule("deserialization.python", "Unsafe deserialization (pickle/marshal/yaml.load)", "Insecure Deserialization",
         "deser", "CWE-502", A08, "High", "Medium", ext(PY), CODE_TAGS,
         pattern=rx(r"\b(c?[Pp]ickle|marshal|dill|shelve|jsonpickle)\.(loads?|open|decode|Unpickler)\(|\byaml\.(load|load_all|unsafe_load)\("),
         exclude=rx(r"yaml\.(load|load_all)\([^)]*Loader\s*=\s*(yaml\.)?(C?SafeLoader|BaseLoader)"), input_boost=True),
    Rule("deserialization.java-dotnet-php-node", "Unsafe native deserialization", "Insecure Deserialization", "deser",
         "CWE-502", A08, "High", "Medium", ext(JAVA, CS, PHP, JS, RB), CODE_TAGS,
         pattern=rx(r"new\s+ObjectInputStream\(|\bXMLDecoder\(|BinaryFormatter|NetDataContractSerializer|LosFormatter|"
                    r"SoapFormatter|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects)|\bunserialize\(\s*\$|"
                    r"Marshal\.load\(|node-serialize|serialize\.unserialize\("), input_boost=True),
    Rule("xxe.parser-config", "XML parser with external entities/DTD enabled", "XML External Entity (XXE)", "xxe",
         "CWE-611", A05, "High", "Medium", ext(PY, CS, PHP, JS), CODE_TAGS,
         pattern=rx(r"resolve_entities\s*=\s*True|load_dtd\s*=\s*True|no_network\s*=\s*False|DtdProcessing\s*=\s*DtdProcessing\.Parse|"
                    r"XmlResolver\s*=\s*new\s+XmlUrlResolver|libxml_disable_entity_loader\(\s*false|LIBXML_NOENT|noent\s*:\s*true")),
    Rule("xxe.java-factory-defaults", "Java XML parser factory without visible hardening", "XML External Entity (XXE)",
         "xxe", "CWE-611", A05, "Medium", "Low", ext(JAVA), CODE_TAGS,
         pattern=rx(r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.newInstance\("),
         status="Needs Manual Review",
         mitigated_if=rx(r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|SUPPORT_DTD|external-general-entities")),
    # ---- path / files
    Rule("path-traversal.user-path", "File path built from request input", "Path Traversal", "path", "CWE-22", A01,
         "High", "Medium", ext(CODE), CODE_TAGS | {"api"},
         pattern=rx(r"(?<![\w.])open\(|send_file\(|os\.path\.join\(|Path\(|readFile(Sync)?\(|createReadStream\(|sendFile\(|"
                    r"res\.download\(|path\.(join|resolve)\(|new\s+File\(|Paths\.get\(|File\.(ReadAllText|ReadAllBytes|OpenRead)\(|"
                    r"\b(fopen|file_get_contents|readfile)\(|\b(include|require)(_once)?\s*\(?\s*\$|filepath\.Join\(|os\.Open\("),
         needs_input=True, exclude=rx(r"secure_filename|send_from_directory|basename\(")),
    Rule("file-upload.client-filename", "Upload stored with client-supplied filename", "Unsafe File Upload", "upload",
         "CWE-434", A04, "High", "Medium", ext(PY, PHP, JS), CODE_TAGS,
         pattern=rx(r"\.save\([^)]*\.filename|move_uploaded_file\([^,]*,\s*[^)]*\$_FILES\[[^\]]+\]\[[\"']name|"
                    r"\.mv\([^)]*\.name\b|originalname"),
         exclude=rx(r"secure_filename|uuid|randomUUID|token_hex")),
    # ---- SSRF / redirect
    Rule("ssrf.user-controlled-url", "Outbound request to a user-controlled URL", "Server-Side Request Forgery", "ssrf",
         "CWE-918", A10, "High", "Medium", ext(CODE), CODE_TAGS | {"api"}, owasp_api="API7:2023-Server Side Request Forgery",
         pattern=rx(r"\b(requests|httpx|urllib3|aiohttp|session|client)\.(get|post|put|delete|patch|head|request)\(|urlopen\(|"
                    r"(?<![\w.])fetch\(|\baxios(\.\w+)?\(|\bgot(\.\w+)?\(|https?\.get\(|new\s+URL\([^)]*\)\.openConnection|"
                    r"HttpClient[^\n]*\.(Get|Post|Send)(Async)?\(|http\.(Get|Post|Head)\(|curl_init\(|file_get_contents\(\s*\$"),
         needs_input=True),
    Rule("open-redirect.user-controlled", "Redirect to a user-controlled location", "Open Redirect", "redirect",
         "CWE-601", A01, "Medium", "Medium", ext(CODE), CODE_TAGS,
         pattern=rx(r"(?<![\w.])redirect\(|res\.redirect\(|HttpResponseRedirect\(|sendRedirect\(|Redirect\(|header\(\s*[\"']Location:"),
         needs_input=True, exclude=rx(r"url_for\(|url_has_allowed_host_and_scheme|is_safe_url")),
    # ---- XSS
    Rule("xss.dom-sink", "Untrusted data written to a DOM HTML sink", "Cross-Site Scripting (XSS)", "xss", "CWE-79",
         A03, "Medium", "Medium", ext(JS, TEMPLATES), CODE_TAGS,
         pattern=rx(r"\.(innerHTML|outerHTML)\s*\+?=|insertAdjacentHTML\(|document\.write(ln)?\(|\.html\(\s*[^)\s\"'`]"),
         exclude=rx(r"\.(innerHTML|outerHTML)\s*\+?=\s*([\"'`])[^\"'`$]*\2\s*;?\s*$|DOMPurify\.sanitize"), input_boost=True),
    Rule("xss.escaping-disabled", "Framework auto-escaping bypassed", "Cross-Site Scripting (XSS)", "xss", "CWE-79", A03,
         "Medium", "Low", lambda p: ext(JS, PY, TEMPLATES, CS, PHP)(p), CODE_TAGS, status="Needs Manual Review",
         pattern=rx(r"dangerouslySetInnerHTML|\bv-html\b|bypassSecurityTrust\w+\(|\|\s*safe\b|\bmark_safe\(|\bMarkup\(|"
                    r"\{%\s*autoescape\s+(false|off)|autoescape\s*=\s*False|Html\.Raw\(|<%-\s|\{\{\{[^}]+\}\}\}"),
         input_boost=True),
    Rule("xss.server-reflected", "Request input reflected in an HTML response", "Cross-Site Scripting (XSS)", "xss",
         "CWE-79", A03, "High", "Medium", ext(PY, JS, PHP), CODE_TAGS,
         pattern=rx(r"return\s+f[\"'][^\"']*<\w|return\s+[\"'][^\"']*<\w[^\"']*[\"']\s*(\+|%)|res\.send\(\s*(`[^`]*<\w[^`]*\$\{|[\"'][^\"']*<\w[^\"']*[\"']\s*\+)|"
                    r"\becho\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)"),
         needs_input=True, exclude=rx(r"escape\(|htmlspecialchars|html\.escape|encodeURIComponent")),
    # ---- CSRF / access / mass assignment
    Rule("csrf.protection-disabled", "CSRF protection disabled or exempted", "Cross-Site Request Forgery (CSRF)", "csrf",
         "CWE-352", A01, "Medium", "Medium", code_or_config, CODE_TAGS | AUTH_TAGS, status="Needs Manual Review",
         pattern=rx(r"@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|WTF_CSRF_CHECK_DEFAULT\s*=\s*False|\.csrf\(\)\.disable\(\)|"
                    r"csrf\(\s*(AbstractHttpConfigurer|c\s*->\s*c)\s*::?\s*disable|\[IgnoreAntiforgeryToken\]|"
                    r"skip_forgery_protection|protect_from_forgery\s+with:\s*:null_session|csrf\s*:\s*false")),
    Rule("mass-assignment.request-body-binding", "Model bound directly to request body", "Mass Assignment", "massassign",
         "CWE-915", A08, "Medium", "Medium", ext(PY, JS, RB, PHP), CODE_TAGS | {"api"},
         owasp_api="API3:2023-Broken Object Property Level Authorization",
         pattern=rx(r"\*\*request\.(json|form|data|get_json\(\))|\.update\(\s*(\*\*)?request\.(json|form|data)|"
                    r"Object\.assign\(\s*[\w.]+\s*,\s*req\.body|\.(create|update|insert|build|updateOne|findByIdAndUpdate)\([^)]*\breq\.body\s*\)|"
                    r"new\s+\w+\(\s*req\.body\s*\)|\{\s*\.\.\.req\.body|params\.permit!|->fill\(\s*\$request->all\(\)|::create\(\s*\$request->all\(\)")),
    Rule("prototype-pollution.deep-merge", "Deep merge of request-controlled object", "Prototype Pollution", "proto",
         "CWE-1321", A08, "Medium", "Medium", ext(JS), CODE_TAGS,
         pattern=rx(r"(_\.(merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)|\$\.extend\(\s*true|deepmerge|\bmerge|\bextend)\([^)]*req\.(body|query|params)")),
    # ---- crypto
    Rule("crypto.weak-hash", "Weak hash algorithm (MD5/SHA-1)", "Insecure Cryptography", "weakhash", "CWE-328", A02,
         "Low", "Low", ext(CODE), AUTH_TAGS, status="Needs Manual Review",
         pattern=rx(r"hashlib\.(md5|sha1)\(|hashlib\.new\(\s*[\"'](md5|sha1)|createHash\(\s*[\"'](md5|sha1)[\"']|"
                    r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"|\b(MD5|SHA1)\.Create\(|new\s+(MD5|SHA1)CryptoServiceProvider|"
                    r"(?<![\w.$])(md5|sha1)\(\s*\$|crypto/md5|crypto/sha1"),
         adjust=weakhash_adjust),
    Rule("crypto.weak-cipher-or-mode", "Weak cipher or ECB mode", "Insecure Cryptography", "weakcrypto", "CWE-327", A02,
         "Medium", "Medium", ext(CODE), AUTH_TAGS,
         pattern=rx(r"MODE_ECB|AES/ECB|[\"']ECB[\"']|CipherMode\.ECB|\bDES\.new\(|\bDES3\.new\(|\bARC4\.new\(|"
                    r"Cipher\.getInstance\(\s*\"(DES|DESede|RC4|Blowfish)|createCipheriv\(\s*[\"'](des|rc4|bf)|TripleDES|RC2\.Create")),
    Rule("crypto.insecure-random", "Non-cryptographic PRNG for a security value", "Insecure Randomness", "prng",
         "CWE-338", A02, "Medium", "Medium", ext(PY, JS, JAVA, CS, PHP, GO), AUTH_TAGS,
         pattern=rx(r"\brandom\.(random|randint|choice|choices|randrange|getrandbits|sample)\(|Math\.random\(\)|"
                    r"new\s+Random\(|\b(rand|mt_rand)\(|math/rand"),
         matcher=lambda line, ctx: bool(re.search(
             r"\brandom\.(random|randint|choice|choices|randrange|getrandbits|sample)\(|Math\.random\(\)|new\s+Random\(|"
             r"\b(rand|mt_rand)\(", line)) and prng_matcher(line, ctx)),
    Rule("tls.verification-disabled", "TLS certificate verification disabled", "Insecure Transport", "tls", "CWE-295",
         A02, "Medium", "High", code_or_config, AUTH_TAGS | CFG_TAGS,
         pattern=rx(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[=:]\s*[\"']?0|"
                    r"InsecureSkipVerify\s*:\s*true|ServerCertificate(Custom)?ValidationCallback\s*=[^;\n]*=>\s*true|"
                    r"DangerousAcceptAnyServerCertificateValidator|_create_unverified_context|cert_reqs\s*=\s*[\"']?(ssl\.)?CERT_NONE|"
                    r"check_hostname\s*=\s*False|curl\s+[^\n|]*(-k\b|--insecure)|strictSSL\s*:\s*false")),
    # ---- authentication / JWT / session
    Rule("auth.jwt.signature-not-verified", "JWT decoded without signature verification", "Broken Authentication (JWT)",
         "jwt", "CWE-347", A07, "High", "High", ext(PY, JS, CS, JAVA, GO), AUTH_TAGS | {"api"},
         owasp_api="API2:2023-Broken Authentication",
         pattern=rx(r"jwt\.decode\([^)]*verify\s*=\s*False|[\"']verify_signature[\"']\s*:\s*False|"
                    r"algorithms?\s*[:=]\s*\[?[^\]\n]*[\"']none[\"']|ValidateIssuerSigningKey\s*=\s*false|"
                    r"RequireSignedTokens\s*=\s*false|parseUnsecuredClaims|SignatureValidator\s*=|jwt\.ParseUnverified\(")),
    Rule("auth.jwt.decode-without-verify-node", "jsonwebtoken decode() does not verify signatures", "Broken Authentication (JWT)",
         "jwt", "CWE-347", A07, "Medium", "Medium", ext(JS), AUTH_TAGS | {"api"}, status="Needs Manual Review",
         owasp_api="API2:2023-Broken Authentication", pattern=rx(r"\bjwt\.decode\("), adjust=jsdecode_adjust),
    Rule("auth.jwt.claims-not-validated", "JWT expiry/issuer/audience validation disabled", "Broken Authentication (JWT)",
         "jwt", "CWE-613", A07, "Medium", "High", ext(PY, JS, CS, JAVA), AUTH_TAGS | {"api"},
         owasp_api="API2:2023-Broken Authentication",
         pattern=rx(r"[\"']verify_(exp|aud|iss)[\"']\s*:\s*False|ignoreExpiration\s*:\s*true|ValidateLifetime\s*=\s*false|"
                    r"ValidateAudience\s*=\s*false|ValidateIssuer\s*=\s*false|RequireExpirationTime\s*=\s*false")),
    Rule("auth.cookie.insecure-flags", "Session cookie without Secure/HttpOnly", "Session Management", "cookie",
         "CWE-614", A05, "Medium", "Medium", code_or_config, AUTH_TAGS,
         pattern=rx(r"(SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|REMEMBER_COOKIE_SECURE)\s*=\s*False|"
                    r"set_cookie\([^)]*(secure|httponly)\s*=\s*False|cookie[^\n]*(secure|httpOnly)\s*:\s*false|"
                    r"(HttpOnly|Secure)\s*=\s*false|cookie_secure\s*=\s*(false|0)")),
    Rule("auth.password.plaintext-compare", "Password compared directly (possible plaintext storage)", "Insecure Password Storage",
         "plainpw", "CWE-256", A07, "Medium", "Low", ext(PY, JS, JAVA, CS, PHP, RB, GO), AUTH_TAGS,
         status="Needs Manual Review",
         pattern=rx(r"(?i)\b[\w.\[\]'\"]*pass(word|wd)?[\w\]'\"]*\s*(===?|!==?|\.equals\()\s*[\w.\[\]'\"(]*pass(word|wd)?"),
         exclude=rx(r"(?i)hash|bcrypt|argon|verify|confirm|repeat|_again|len\(|length|None|null|undefined")),
    # ---- misconfiguration in code
    Rule("config.debug-enabled", "Debug mode enabled", "Security Misconfiguration", "debug", "CWE-489", A05, "Medium",
         "Medium", code_or_config, CFG_TAGS | CODE_TAGS,
         pattern=rx(r"\bapp\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b|\bapp\.debug\s*=\s*True|"
                    r"\.UseDeveloperExceptionPage\(\)|^\s*FLASK_DEBUG\s*=\s*1"),
         adjust=devpage_adjust),
    Rule("config.cors-wildcard", "CORS allows any origin", "Security Misconfiguration", "cors", "CWE-942", A05, "Low",
         "Medium", code_or_config, CFG_TAGS | CODE_TAGS | {"api"}, owasp_api="API8:2023-Security Misconfiguration",
         pattern=rx(r"Access-Control-Allow-Origin[\"']?\s*[,:\s]\s*[\"']?\*|origins?\s*[:=]\s*[\"']\*[\"']|"
                    r"CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|AllowAnyOrigin\(\)|origin\s*:\s*true"),
         adjust=cors_adjust),
    Rule("config.allowed-hosts-wildcard", "ALLOWED_HOSTS allows any host", "Security Misconfiguration", "debug",
         "CWE-16", A05, "Low", "High", ext(PY), CFG_TAGS, pattern=rx(r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']\s*\]")),
    Rule("config.actuator-exposed", "All management endpoints exposed", "Sensitive Information Disclosure", "exposure",
         "CWE-200", A05, "Medium", "High", code_or_config, CFG_TAGS,
         pattern=rx(r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*[\"']?\*|include\s*:\s*[\"']\*[\"']")),
    Rule("errors.stack-trace-in-response", "Exception details returned to the client", "Insecure Error Handling",
         "errors", "CWE-209", A04, "Low", "Medium", ext(PY, JS, PHP, JAVA, CS), CODE_TAGS | {"api"},
         pattern=rx(r"(return|jsonify|Response|HttpResponse)[^\n]*traceback\.format_exc\(\)|"
                    r"res\.(status\(\d+\)\.)?(send|json)\([^)]*\b(err|error|e|ex)\.stack|"
                    r"return\s+(str|repr)\(\s*(e|err|exc|ex)\s*\)|jsonify\([^)]*str\(\s*(e|err|exc|ex)\s*\)|"
                    r"printStackTrace\(\s*response\.getWriter|e\.printStackTrace\(\)"),
         adjust=lambda line, ctx: {"severity": "Medium", "note": "stack trace exposed"} if re.search(r"traceback|\.stack", line) else None),
    Rule("logging.sensitive-data", "Sensitive value written to logs", "Sensitive Information Disclosure", "logging",
         "CWE-532", A09, "Low", "Low", ext(CODE), CODE_TAGS, status="Needs Manual Review",
         pattern=rx(r"(?i)\b(log(ger)?|console|print|System\.out|logging)\.?\w*\([^)]*\b(password|passwd|secret|api_?key|"
                    r"access_?token|refresh_?token|private_?key|credit_?card|ssn)\b"),
         exclude=rx(r"(?i)(invalid|missing|wrong|incorrect|reset|expired|required|changed|updated)\s+(password|token|secret)|"
                    r"password\s+(reset|changed|updated|is\s+required)")),
    Rule("race.insecure-tempfile", "Insecure temporary file name generation", "Race Condition", "tempfile", "CWE-377",
         A04, "Medium", "High", ext(PY), CODE_TAGS, pattern=rx(r"\btempfile\.mktemp\(|\bos\.tempnam\(|\bos\.tmpnam\(")),
    Rule("perms.world-writable", "World-writable file permissions", "Security Misconfiguration", "perms", "CWE-732",
         A05, "Medium", "High", lambda p: ext(CODE)(p) or is_shellish(p), CODE_TAGS | CFG_TAGS,
         pattern=rx(r"chmod\([^)]*0o?777|chmod\s+(-R\s+)?(0?777|a\+w|o\+w)|os\.chmod\([^)]*0o?666")),
    # ---- containers / k8s / compose
    Rule("container.docker.user-root", "Container explicitly runs as root", "Container Security", "container", "CWE-250",
         A05, "Medium", "High", is_dockerfile, CFG_TAGS, pattern=rx(r"^\s*USER\s+(root|0)(\s|:|$)", re.I)),
    Rule("container.docker.no-user", "Dockerfile has no USER instruction (defaults to root)", "Container Security",
         "container", "CWE-250", A05, "Low", "Medium", is_dockerfile, CFG_TAGS, status="Needs Manual Review",
         file_check=docker_no_user_check),
    Rule("container.docker.unpinned-base-image", "Base image not pinned (latest or no tag)", "Supply Chain",
         "image", "CWE-1357", A08, "Low", "High", is_dockerfile, CFG_TAGS,
         pattern=rx(r"^\s*FROM\s+(--platform=\S+\s+)?([^\s:@]+(\s|$)|[^\s@]+:latest\b)", re.I),
         exclude=rx(r"^\s*FROM\s+(scratch|\$\{?\w+\}?)\b", re.I)),
    Rule("container.docker.secret-in-env", "Secret-like value set via ENV/ARG (persists in image layers)",
         "Secrets Management", "secret", "CWE-538", A05, "Medium", "Medium", is_dockerfile, CFG_TAGS | {"secrets"},
         status="Needs Manual Review",
         pattern=rx(r"^\s*(ENV|ARG)\s+\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)\w*\s*[= ]\s*[^\s$]\S*", re.I)),
    Rule("supply-chain.remote-script-pipe", "Remote script piped to a shell", "Supply Chain", "remote-script",
         "CWE-494", A08, "Medium", "High", is_shellish, CFG_TAGS,
         pattern=rx(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b|^\s*ADD\s+https?://", re.I)),
    Rule("container.privileged", "Privileged container", "Container Security", "container", "CWE-250", A05, "High",
         "High", is_yaml, CFG_TAGS, pattern=rx(r"^\s*privileged\s*:\s*true\b")),
    Rule("container.privilege-escalation", "allowPrivilegeEscalation enabled", "Container Security", "container",
         "CWE-250", A05, "Medium", "High", is_yaml, CFG_TAGS, pattern=rx(r"allowPrivilegeEscalation\s*:\s*true\b")),
    Rule("container.host-namespaces", "Host network/PID/IPC namespace shared", "Container Security", "container",
         "CWE-250", A05, "Medium", "High", is_yaml, CFG_TAGS,
         pattern=rx(r"\b(hostNetwork|hostPID|hostIPC)\s*:\s*true\b|network_mode\s*:\s*[\"']?host\b|\bpid\s*:\s*[\"']?host\b")),
    Rule("container.docker-socket-mount", "Docker socket mounted into a container", "Container Security", "container",
         "CWE-250", A05, "High", "High", lambda p: is_yaml(p) or is_dockerfile(p), CFG_TAGS,
         pattern=rx(r"/var/run/docker\.sock")),
    Rule("container.runs-as-root-k8s", "Workload configured to run as root", "Container Security", "container",
         "CWE-250", A05, "Medium", "High", is_yaml, CFG_TAGS, pattern=rx(r"\brunAsUser\s*:\s*0\b|\brunAsNonRoot\s*:\s*false\b")),
    Rule("container.dangerous-capabilities", "Dangerous Linux capabilities added", "Container Security", "container",
         "CWE-250", A05, "High", "High", is_yaml, CFG_TAGS, matcher=caps_matcher),
    Rule("container.hostpath-volume", "hostPath volume mounted", "Container Security", "container", "CWE-250", A05,
         "Low", "Medium", is_yaml, CFG_TAGS, status="Needs Manual Review", pattern=rx(r"^\s*hostPath\s*:")),
    # ---- terraform / cloud
    Rule("iac.network.open-to-world", "Ingress open to 0.0.0.0/0", "Infrastructure Exposure", "iac-network",
         "CWE-284", A05, "Medium", "Medium", lambda p: is_terraform(p) or is_yaml(p) or p.endswith(".json"), CFG_TAGS,
         pattern=rx(r"[\"']0\.0\.0\.0/0[\"']|[\"']::/0[\"']|sourceAddressPrefix[\"']?\s*:\s*[\"'](\*|Internet)[\"']"),
         adjust=cidr_adjust),
    Rule("iac.storage.public-acl", "Storage made publicly accessible", "Infrastructure Exposure", "iac-storage",
         "CWE-732", A05, "High", "High", lambda p: is_terraform(p) or is_yaml(p), CFG_TAGS,
         pattern=rx(r"acl\s*=\s*\"public-read(-write)?\"|publicly_accessible\s*=\s*true|"
                    r"(block_public_acls|block_public_policy|restrict_public_buckets|ignore_public_acls)\s*=\s*false|"
                    r"allow_blob_public_access\s*=\s*true|public_network_access_enabled\s*=\s*true")),
    Rule("iac.encryption-disabled", "Encryption at rest/in transit disabled", "Infrastructure Exposure", "iac-storage",
         "CWE-311", A02, "Medium", "High", lambda p: is_terraform(p) or is_yaml(p), CFG_TAGS,
         pattern=rx(r"\b(encrypted|storage_encrypted|enable_encryption|encryption_enabled|enable_https_traffic_only|"
                    r"https_only|ssl_enforcement_enabled|transit_encryption_enabled)\s*=\s*false\b")),
    Rule("iac.iam.wildcard", "IAM policy with wildcard action or principal", "Excessive Permissions", "iam", "CWE-269",
         A01, "High", "Medium", lambda p: is_terraform(p) or p.endswith(".json") or is_yaml(p), CFG_TAGS,
         pattern=rx(r"[\"']Action[\"']\s*:\s*[\"']\*[\"']|\bactions\s*=\s*\[\s*\"\*\"\s*\]|[\"']Principal[\"']\s*:\s*[\"']\*[\"']|"
                    r"[\"']AWS[\"']\s*:\s*[\"']\*[\"']|identifiers\s*=\s*\[\s*\"\*\"\s*\]|role_definition_name\s*=\s*\"Owner\"")),
    Rule("iac.tls.min-version", "Minimum TLS version below 1.2", "Insecure Transport", "tlsconf", "CWE-326", A02,
         "Medium", "High", lambda p: is_terraform(p) or is_yaml(p), CFG_TAGS,
         pattern=rx(r"(min_tls_version|minimum_tls_version|ssl_minimal_tls_version_enforced|minimumTlsVersion)\s*[=:]\s*[\"']?(TLS1_0|TLS1_1|1\.0|1\.1|TLSv1|TLSv1_1|Tls10|Tls11)\b")),
    # ---- web servers
    Rule("webserver.legacy-tls", "Legacy TLS/SSL protocol enabled", "Insecure Transport", "tlsconf", "CWE-326", A02,
         "Medium", "High", lambda p: is_web_server_conf(p) or is_yaml(p) or p.endswith((".conf", ".cfg")), CFG_TAGS,
         matcher=legacy_tls_matcher),
    Rule("webserver.weak-ciphers", "Weak TLS cipher suites enabled", "Insecure Transport", "tlsconf", "CWE-327", A02,
         "Medium", "Medium", is_web_server_conf, CFG_TAGS,
         pattern=rx(r"(?i)(ssl_ciphers|SSLCipherSuite)[^\n]*(?<![!\-\w])(RC4|DES|3DES|NULL|EXPORT|MD5)\b")),
    Rule("webserver.directory-listing", "Directory listing enabled", "Sensitive Information Disclosure", "webconf",
         "CWE-548", A05, "Low", "High", is_web_server_conf, CFG_TAGS,
         pattern=rx(r"^\s*autoindex\s+on\b|^\s*Options\s+[^#\n]*(?<![-\w])\+?Indexes\b", re.I)),
    Rule("webserver.version-disclosure", "Server version banner enabled", "Sensitive Information Disclosure", "webconf",
         "CWE-200", A05, "Informational", "High", is_web_server_conf, CFG_TAGS,
         pattern=rx(r"^\s*server_tokens\s+on\b|^\s*ServerTokens\s+(Full|OS|Major|Minor|Min)\b|^\s*ServerSignature\s+On\b", re.I)),
    # ---- CI/CD
    Rule("cicd.gha.script-injection", "Untrusted GitHub event data interpolated into a script", "CI/CD Security",
         "cicd", "CWE-94", A03, "High", "Medium", is_workflow, CFG_TAGS, matcher=gha_injection_matcher),
    Rule("cicd.gha.pull-request-target", "pull_request_target trigger", "CI/CD Security", "cicd", "CWE-829", A08,
         "Medium", "Medium", is_workflow, CFG_TAGS, pattern=rx(r"^\s*(-\s*)?pull_request_target\b|\bon\s*:\s*\[?[^\n]*pull_request_target"),
         adjust=prt_adjust),
    Rule("cicd.gha.write-all-permissions", "Workflow grants write-all permissions", "CI/CD Security", "cicd", "CWE-250",
         A05, "Medium", "High", is_workflow, CFG_TAGS, pattern=rx(r"permissions\s*:\s*write-all")),
    Rule("cicd.gha.missing-permissions", "Workflow without explicit permissions block", "CI/CD Security", "cicd",
         "CWE-250", A05, "Low", "Medium", is_workflow, CFG_TAGS, status="Needs Manual Review",
         file_check=gha_permissions_check),
    Rule("cicd.gha.unpinned-action", "Third-party action not pinned to a commit SHA", "Supply Chain", "cicd",
         "CWE-829", A08, "Informational", "High", is_workflow, CFG_TAGS, matcher=uses_unpinned_matcher),
    Rule("cicd.secret-echo", "Secret printed in CI logs", "Secrets Management", "logging", "CWE-532", A09, "Medium",
         "Medium", is_ci_file, CFG_TAGS | {"secrets"},
         pattern=rx(r"\b(echo|printf|Write-Host)\b[^\n]*(\$\{\{\s*secrets\.|\$\(?\w*(TOKEN|SECRET|PASSWORD|API_KEY)\w*\)?)")),
    # ---- app config files
    Rule("config.env-file-committed", "Environment file present in repository", "Secrets Management", "envfile",
         "CWE-538", A05, "Medium", "Medium", is_env_file, CFG_TAGS | {"secrets"}, status="Needs Manual Review",
         file_check=env_file_check),
    # ---- meta: content that targets AI reviewers
    Rule("meta.prompt-injection-marker", "Embedded instruction targeting AI agents", "Untrusted Content",
         "prompt-injection", "CWE-1427", A04, "Informational", "Medium", any_text, {"meta"}, skip_comments=False,
         status="Needs Manual Review",
         pattern=rx(r"(?i)\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)|"
                    r"\b(AI|LLM|assistant|agent|reviewer|claude|chatgpt|copilot)\b[^\n]{0,40}\b(do\s+not|don't|never)\s+(report|flag|mention)|"
                    r"\b(mark|report|classify)\s+(this|these|all)\s+(file|code|findings?)\s+as\s+(safe|secure|false\s+positive)")),
]

RULE_INDEX = {r.id: r for r in RULES}

# Secret rule metadata (detection itself uses scr_common.SECRET_PATTERNS)
SECRET_RULE_META: Dict[str, Dict[str, str]] = {
    "aws-access-key-id": dict(title="AWS access key ID", severity="Medium", confidence="High"),
    "aws-secret-access-key": dict(title="AWS secret access key", severity="Critical", confidence="Medium"),
    "github-token": dict(title="GitHub token", severity="High", confidence="High"),
    "github-fine-grained-pat": dict(title="GitHub fine-grained personal access token", severity="High", confidence="High"),
    "gitlab-token": dict(title="GitLab personal access token", severity="High", confidence="High"),
    "slack-token": dict(title="Slack token", severity="High", confidence="High"),
    "slack-webhook": dict(title="Slack incoming webhook URL", severity="Medium", confidence="High"),
    "stripe-live-key": dict(title="Stripe live secret key", severity="Critical", confidence="High"),
    "stripe-test-key": dict(title="Stripe test key", severity="Low", confidence="High"),
    "google-api-key": dict(title="Google API key", severity="Medium", confidence="Medium"),
    "llm-api-key": dict(title="AI/LLM provider API key", severity="High", confidence="Medium"),
    "private-key": dict(title="Private key material", severity="High", confidence="High"),
    "jwt": dict(title="Hardcoded JSON Web Token", severity="Medium", confidence="Medium"),
    "connection-string-password": dict(title="Credentials in database/broker connection string", severity="High", confidence="High"),
    "dotnet-connection-string-password": dict(title="Password in .NET connection string", severity="High", confidence="Medium"),
    "generic-secret-assignment": dict(title="Hardcoded secret or password", severity="High", confidence="Medium"),
}
