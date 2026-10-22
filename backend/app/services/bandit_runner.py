"""Optional Bandit (Python security linter) runner.

Wraps the `bandit` CLI as a subprocess. If the binary is missing, returns an
empty list — never crashes — so SAST still works on this dev machine or any
environment that hasn't installed bandit. Add `bandit` to requirements.txt to
enable it (best practice in the containerised build).
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from .secrets_scan import _line_of, _stable_id

logger = logging.getLogger(__name__)

_BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _owasp_for_cwe(cwe: str) -> str:
    return {
        "78": "A03:2021 - Injection",
        "89": "A03:2021 - Injection",
        "94": "A03:2021 - Injection",
        "95": "A03:2021 - Injection",
        "502": "A08:2021 - Software and Data Integrity Failures",
        "327": "A02:2021 - Cryptographic Failures",
        "295": "A02:2021 - Cryptographic Failures",
        "489": "A05:2021 - Security Misconfiguration",
    }.get(cwe, "A06:2021 - Vulnerable and Outdated Components")


def is_available() -> bool:
    return shutil.which("bandit") is not None


def scan_path(root: Path) -> list[dict]:
    """Run `bandit -r -f json` over ``root``; return findings (empty if N/A)."""
    if not is_available():
        logger.info("bandit not on PATH — skipping")
        return []

    try:
        proc = subprocess.run(
            ["bandit", "-r", str(root), "-f", "json", "-q"],
            capture_output=True, text=True, timeout=120,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("bandit run failed (%s); skipping", exc)
        return []

    # Bandit writes JSON regardless of issue count; `proc.returncode` is 0 if
    # no HIGH/MEDIUM issues, 1 if any, 2 on usage/app error. We only bail on 2.
    if proc.returncode not in (0, 1):
        logger.warning("bandit error: %s", proc.stderr.strip())
        return []

    try:
        report = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        logger.warning("bandit JSON parse failed (%s)", exc)
        return []

    findings: list[dict] = []
    # Bandit silently skips files outside `--recursive`; results are under
    # `results` regardless.
    for r in report.get("results", []):
        cwe = (r.get("issue_cwe") or {}).get("id", "")
        severity = _BANDIT_SEV.get(
            (r.get("issue_severity") or "").upper(), "low"
        )
        path = r.get("filename", "")
        if root in Path(path).parents:
            rel = Path(path).relative_to(root).as_posix()
        else:
            rel = Path(path).name
        line = int(r.get("line_number") or 1)
        rule_id = f"bandit:{r.get('test_id', 'B???')}"
        findings.append({
            "id": _stable_id(rule_id, rel, line),
            "pluginid": rule_id,
            "name": r.get("test_name", "Bandit finding"),
            "risk": severity,
            "confidence": (r.get("issue_confidence") or "MEDIUM").lower(),
            "cwe": str(cwe),
            "cweid": str(cwe),
            "owasp": _owasp_for_cwe(str(cwe)),
            "url": f"{rel}:{line}",
            "file": rel,
            "line": line,
            "param": "",
            "evidence": (r.get("issue_text") or "")[:160],
            "description": (r.get("issue_text") or "Issue reported by bandit."),
            "solution": "See the Bandit rule documentation for remediation "
                        "guidance; usually validating/sanitising input or "
                        "using a safer standard-library primitive.",
            "language": "python",
            "source": "sast:bandit",
        })

    logger.info("bandit scan: %d finding(s)", len(findings))
    return findings
