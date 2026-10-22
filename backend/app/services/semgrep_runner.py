"""Optional Semgrep (multi-language SAST) runner.

Wraps the `semgrep` CLI as a subprocess. If the binary is missing, returns
an empty list — never crashes. Best results come from installing it (the
Docker image does; dev machine doesn't).
"""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def is_available() -> bool:
    return shutil.which("semgrep") is not None


def _owasp_for(rule: dict) -> str:
    for cwe in rule.get("metadata", {}).get("cwe", []) or []:
        if isinstance(cwe, str):
            # strings look like "CWE-79 Improper Neutralization..."
            cid = cwe.split()[0].upper().replace("CWE-", "")
            return {
                "78": "A03:2021 - Injection", "79": "A03:2021 - Injection",
                "89": "A03:2021 - Injection", "94": "A03:2021 - Injection",
                "95": "A03:2021 - Injection", "502": "A08:2021 - Software "
                        "and Data Integrity Failures",
                "327": "A02:2021 - Cryptographic Failures",
                "295": "A02:2021 - Cryptographic Failures",
                "489": "A05:2021 - Security Misconfiguration",
            }.get(cid, "A06:2021 - Vulnerable and Outdated Components")
    return "A06:2021 - Vulnerable and Outdated Components"


def _stable_id(rule_id: str, file: str, line: int) -> str:
    h = hashlib.sha1(f"{rule_id}|{file}|{line}".encode()).hexdigest()
    return str(int(h[:12], 16))


def scan_path(root: Path) -> list[dict]:
    """Run `semgrep --json` over ``root``; return findings (empty if N/A)."""
    if not is_available():
        logger.info("semgrep not on PATH — skipping")
        return []

    try:
        proc = subprocess.run(
            ["semgrep", "--json", "--quiet", "--config", "auto",
             "--metrics=off", "--no-rewrite-rule-ids", str(root)],
            capture_output=True, text=True, timeout=600,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("semgrep run failed (%s); skipping", exc)
        return []

    if proc.returncode not in (0, 1):  # 0=no findings, 1=findings, !0/1 = err
        logger.warning("semgrep error: %s", proc.stderr.strip()[:200])
        return []

    try:
        report = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        logger.warning("semgrep JSON parse failed (%s)", exc)
        return []

    findings: list[dict] = []
    for r in report.get("results", []):
        path_str = r.get("path", "")
        try:
            rel = str(Path(path_str).relative_to(root))
        except ValueError:
            rel = Path(path_str).name
        line = r.get("start", {}).get("line", 1)
        rule_id = r.get("check_id", "semgrep")
        sev = _SEV.get((r.get("extra", {}).get("severity") or "WARNING").upper(),
                        "medium")
        cwe = ((r.get("extra", {}).get("metadata", {}) or {})
               .get("cwe", [""])[0] or "")
        cwe_id = cwe.split()[0].upper().replace("CWE-", "") if cwe else ""
        findings.append({
            "id": _stable_id(rule_id, rel, line),
            "pluginid": rule_id,
            "name": r.get("extra", {}).get("message", rule_id),
            "risk": sev,
            "confidence": "high",
            "cwe": cwe_id,
            "cweid": cwe_id,
            "owasp": _owasp_for(r.get("extra", {}).get("metadata", {}) or {}),
            "url": f"{rel}:{line}",
            "file": rel,
            "line": line,
            "param": "",
            "evidence": (r.get("extra", {}).get("lines") or "")[:160],
            "description": r.get("extra", {}).get("message", "Semgrep rule "
                                   "matched. See rule metadata for details."),
            "solution": "Apply the remediation guidance from the matched "
                        "semgrep rule's metadata (the `fix` or `message` "
                        "field), and add a regression test.",
            "language": (r.get("extra", {}).get("metadata", {}) or {})
                        .get("technology", ["unknown"])[0]
                        if isinstance((r.get("extra", {})
                                       .get("metadata", {}) or {})
                                      .get("technology"), list) else "unknown",
            "source": "sast:semgrep",
        })

    logger.info("semgrep scan: %d finding(s)", len(findings))
    return findings
