"""Dependency-free heuristic source-code vulnerability detector.

Linear file scan with pattern matching (no AST, no external tools). Always
runs so SAST works even when semgrep/bandit are absent.

Pattern families covered:
  * SQL injection          — f-string / % / + concatenation into SQL
  * Cross-site scripting   — innerHTML / dangerouslySetInnerHTML / v-html
  * Code execution         — eval / exec / new Function / child_process
  * Insecure deserialisation — pickle.loads / yaml.load (unsafe)
  * Command injection      — shell=True / os.system
  * Weak crypto            — md5/sha1 for passwords, random for secrets
  * Insecure transport     — verify=False
  * Production hygiene     — DEBUG=True, debugger;, console.log
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from .secrets_scan import _iter_files, _line_of, _stable_id

logger = logging.getLogger(__name__)

_EXT_BY_LANG = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".vue": "javascript",
}

# (rule_id, title, severity, cwe, langs, pattern, description, solution)
_PATTERNS: list[tuple] = []
_PATTERNS += [
    # ---- Python: SQL injection ---------------------------------------------
    (
        "sentinel:sast.py.sqli_fstring",
        "SQL Injection via f-string concatenation",
        "high", "89", {"python"},
        re.compile(
            r"\b(execute|executemany)\s*\(\s*f[\"'].*\b(SELECT|INSERT|UPDATE|"
            r"DELETE|FROM|WHERE|VALUES)\b", re.I),
        "A SQL statement built with an f-string is executed directly. "
        "User input concatenated into the query enables SQL injection.",
        "Use a parameterised query: `cursor.execute(sql, (params,))`. "
        "Never interpolate user data into SQL strings.",
    ),
    (
        "sentinel:sast.py.sqli_percent",
        "SQL Injection via `%` formatting",
        "high", "89", {"python"},
        re.compile(
            r"\b(execute|executemany)\s*\(\s*[\"'].*%s.*[\"']\s*%\s*[\(\{]",
            re.I),
        "A SQL query interpolates values with `%` formatting, passing user "
        "input unparameterised to the database.",
        "Use DB-API parameter substitution (`?` / `%s` placeholders passed "
        "as separate arguments) so the driver escapes them.",
    ),
    (
        "sentinel:sast.py.sqli_plus",
        "SQL Injection via `+` string concatenation",
        "high", "89", {"python"},
        re.compile(r"\b(execute|executemany)\s*\(\s*[\"'].+[\"']\s*\+\s*\w+", re.I),
        "A SQL query is built by concatenating a string with `+`. User "
        "input may flow into the query unsanitised.",
        "Refactor to parameterised queries; never concatenate input into SQL.",
    ),
    # ---- Python: code execution -------------------------------------------
    (
        "sentinel:sast.py.eval",
        "Use of `eval()` with input risk",
        "high", "94", {"python"},
        re.compile(r"\beval\s*\("),
        "`eval()` runs arbitrary Python from a string; any user input that "
        "reaches it grants attackers remote code execution.",
        "Replace `eval` with `ast.literal_eval` for literals / "
        "`json.loads` for JSON; never accept untrusted input.",
    ),
    (
        "sentinel:sast.py.exec",
        "Use of `exec()` with input risk",
        "high", "94", {"python"},
        re.compile(r"\bexec\s*\("),
        "`exec()` runs arbitrary Python code. Any user-controlled data "
        "reaching it results in RCE.",
        "Remove `exec` and use a safe deserialisation format (JSON) instead.",
    ),
    (
        "sentinel:sast.py.pickle",
        "Insecure deserialisation via pickle",
        "high", "502", {"python"},
        re.compile(r"\bpickle\.(loads?|Unpickler)\b"),
        "`pickle.loads` can execute arbitrary code during deserialisation. "
        "Never unpickle untrusted data.",
        "Use a safe format (JSON) for untrusted input, or sign/verify a "
        "pickle stream with HMAC over an authenticated channel.",
    ),
    (
        "sentinel:sast.py.yaml_unsafe",
        "Insecure YAML deserialisation",
        "high", "502", {"python"},
        re.compile(r"\byaml\.load\b\s*\([^)]*\)"),
        "`yaml.load` without an explicit SafeLoader can construct arbitrary "
        "Python objects from YAML input.",
        "Use `yaml.safe_load` (or `yaml.load(..., Loader=yaml.SafeLoader)`).",
    ),
    (
        "sentinel:sast.py.shell_true",
        "Command injection via `shell=True`",
        "high", "78", {"python"},
        re.compile(r"(?i)shell\s*=\s*True"),
        "Running subprocess with `shell=True` with any user-controlled "
        "argument enables shell metacharacter injection.",
        "Drop `shell=True` and pass args as a list, or rigorously validate "
        "and escape interpolated values.",
    ),
    (
        "sentinel:sast.py.os_system",
        "Use of `os.system` (command injection risk)",
        "high", "78", {"python"},
        re.compile(r"\bos\.system\s*\("),
        "`os.system` runs the command in a shell; user input can inject "
        "arbitrary commands.",
        "Use `subprocess.run([...], shell=False)` with arguments as a list.",
    ),
    # ---- Python: weak crypto -----------------------------------------------
    (
        "sentinel:sast.py.weak_hash",
        "Weak password hash (MD5/SHA1)",
        "medium", "916", {"python"},
        re.compile(r"(?i)(hashlib\.(md5|sha1)|md5\(|sha1\()\b"),
        "MD5/SHA1 are not suitable for password storage — they are fast and "
        "broken for collision resistance.",
        "Use `hashlib.scrypt` / `bcrypt` / `argon2-cffi` with a random salt "
        "and a per-password work factor.",
    ),
    (
        "sentinel:sast.py.random_secret",
        "Insecure RNG for secrets (`random`)",
        "medium", "338", {"python"},
        re.compile(r"(?i)\brandom\.(choice|randint|random)\b"),
        "The `random` module is not cryptographically secure; tokens / "
        "secrets generated with it can be predicted.",
        "Use the `secrets` module (or `os.urandom`) for any token, session "
        "id, or key material.",
    ),
    # ---- Production config --------------------------------------------------
    (
        "sentinel:sast.py.debug_true",
        "`DEBUG=True` committed in source",
        "medium", "489", {"python"},
        re.compile(r"(?i)\bDEBUG\s*=\s*True\b"),
        "A debug flag is set to True in source. Detailed error pages leak "
        "stack traces and internal paths to attackers.",
        "Read DEBUG from the environment and default to False in production "
        "(e.g. `DEBUG = os.getenv('DEBUG') == '1'`).",
    ),
    (
        "sentinel:sast.py.verify_false",
        "TLS verification disabled (`verify=False`)",
        "medium", "295", {"python"},
        re.compile(r"(?i)verify\s*=\s*False"),
        "TLS certificate verification is disabled, exposing the request to "
        "man-in-the-middle attacks.",
        "Never disable verification in production. If testing against a "
        "self-signed cert, configure a custom CA bundle instead.",
    ),
]

_PATTERNS += [
    # ---- JS / TS: XSS -------------------------------------------------------
    (
        "sentinel:sast.js.innerhtml",
        "DOM XSS via `innerHTML`",
        "high", "79", {"javascript", "typescript"},
        re.compile(r"\.innerHTML\s*="),
        "Assigning to `.innerHTML` with user-controlled data injects HTML "
        "or scripts into the DOM (stored or reflected XSS).",
        "Use `textContent` for plain text, or sanitise HTML with DOMPurify "
        "before injecting. Apply a strict Content-Security-Policy.",
    ),
    (
        "sentinel:sast.js.dangerouslyset",
        "XSS via `dangerouslySetInnerHTML`",
        "high", "79", {"javascript", "typescript"},
        re.compile(r"dangerouslySetInnerHTML"),
        "React's escape hatch `dangerouslySetInnerHTML` bypasses output "
        "encoding; user input bound here causes XSS.",
        "Avoid `dangerouslySetInnerHTML` for user content. If you must, "
        "sanitise with DOMPurify first.",
    ),
    (
        "sentinel:sast.js.v_html",
        "XSS via `v-html` (Vue)",
        "high", "79", {"javascript", "typescript"},
        re.compile(r"\bv-html\b"),
        "Vue's `v-html` renders raw HTML; user input bound here is XSS.",
        "Use `{{ }}` text interpolation, or sanitise with DOMPurify before "
        "binding with `v-html`.",
    ),
    # ---- JS / TS: code execution -------------------------------------------
    (
        "sentinel:sast.js.eval",
        "Use of `eval()` in JS",
        "high", "95", {"javascript", "typescript"},
        re.compile(r"\beval\s*\("),
        "`eval` executes arbitrary JS. User input reaching it gives "
        "attackers script execution in the page or Node process.",
        "Replace `eval` with `JSON.parse` or a sandboxed expression "
        "evaluator; never pass user input to `eval`.",
    ),
    (
        "sentinel:sast.js.new_function",
        "Use of `new Function()` (eval-equivalent)",
        "high", "95", {"javascript", "typescript"},
        re.compile(r"\bnew\s+Function\s*\("),
        "`new Function(...)` compiles and runs arbitrary JS at runtime — "
        "equivalent to `eval` for injection risk.",
        "Avoid dynamic code generation. Parse input with JSON or a sandboxed "
        "expression evaluator instead.",
    ),
    (
        "sentinel:sast.js.child_process",
        "Command injection via `child_process.exec`",
        "high", "78", {"javascript", "typescript"},
        re.compile(r"(?i)\bchild_process\b[^;]*\bexec\b\s*\("),
        "`child_process.exec` runs the command in a shell; user input can "
        "inject shell metacharacters.",
        "Use `child_process.execFile` or `spawn` with args as an array "
        "(`shell: false`).",
    ),
    # ---- Production hygiene (JS/TS) ---------------------------------------
    (
        "sentinel:sast.js.debugger_stmt",
        "Committed `debugger;` statement",
        "low", "489", {"javascript", "typescript"},
        re.compile(r"\bdebugger\s*;"),
        "A `debugger;` statement pauses execution in devtools — committed "
        "leftovers aid attackers in reverse-engineering.",
        "Remove the `debugger;` statement. Lint with `no-debugger` to "
        "prevent future regressions.",
    ),
    (
        "sentinel:sast.js.console_log",
        "Verbose `console.log` left in source",
        "low", "532", {"javascript", "typescript"},
        re.compile(r"\bconsole\.(log|debug|info)\s*\("),
        "A console logging call is committed. It can leak secrets, PII, or "
        "internal state to any JS console reader.",
        "Strip non-essential logging in production; use a logger with levels "
        "and redaction instead.",
    ),
]


_OWASP = {
    "89": "A03:2021 - Injection",
    "78": "A03:2021 - Injection",
    "79": "A03:2021 - Injection",
    "94": "A03:2021 - Injection",
    "95": "A03:2021 - Injection",
    "502": "A08:2021 - Software and Data Integrity Failures",
    "916": "A02:2021 - Cryptographic Failures",
    "338": "A02:2021 - Cryptographic Failures",
    "295": "A02:2021 - Cryptographic Failures",
    "489": "A05:2021 - Security Misconfiguration",
    "532": "A09:2021 - Security Logging and Monitoring Failures",
}

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _finding(rule_id, title, severity, cwe, file, line, excerpt,
             description, solution, lang) -> dict:
    owasp = _OWASP.get(cwe, "A06:2021 - Vulnerable and Outdated Components")
    return {
        "id": _stable_id(rule_id, file, line),
        "pluginid": rule_id,
        "name": title,
        "risk": severity,
        "confidence": "high",
        "cwe": cwe,
        "cweid": cwe,
        "owasp": owasp,
        "url": f"{file}:{line}",
        "file": file,
        "line": line,
        "param": "",
        "evidence": excerpt,
        "description": description,
        "solution": solution,
        "language": lang,
        "source": "sast:heuristic",
    }


def scan_path(root: Path) -> list[dict]:
    """Run every heuristic pattern over every source file under ``root``."""
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()

    for path in _iter_files(root):
        lang = _EXT_BY_LANG.get(path.suffix.lower())
        if not lang:
            continue
        rel = path.relative_to(root).as_posix()

        try:
            raw = path.read_bytes()
            if b"\x00" in raw[:2048]:
                continue
            text = raw.decode("utf-8", errors="ignore")
        except OSError:
            continue

        for rule_id, title, sev, cwe, langs, pattern, desc, sol in _PATTERNS:
            if lang not in langs:
                continue
            for m in pattern.finditer(text):
                line = _line_of(text, m.start())
                key = (rule_id, line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_finding(
                    rule_id, title, sev, cwe, rel, line,
                    m.group(0).strip()[:120], desc, sol, lang,
                ))

    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["risk"], 9))
    logger.info("heuristics scan: %d finding(s) under %s",
                len(findings), root)
    return findings



