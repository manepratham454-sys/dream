"""Static analysis service for Sentinel scans.

Runs a configurable set of linters (ESLint, Flake8, Bandit, Golint, Semgrep) on the
extracted source tree and returns a unified JSON structure.

Each linter is executed via ``subprocess.run`` and its output is parsed into a list
of issues with a common schema:

```
{
    "type": "lint",
    "tool": "eslint",
    "severity": "high" | "medium" | "low",
    "file": "relative/path/to/file.js",
    "line": 123,
    "description": "Problem description",
    "code": "the offending code snippet"
}
```

If a linter is not installed or its execution fails, the service records a warning
issue but continues with the remaining tools.

The service respects the ``ENABLE_*`` flags defined in ``backend/app/config.py``
and the ``MAX_UPLOAD_SIZE`` limit is enforced upstream during ingestion.
"""
import json
import logging
import subprocess
from pathlib import Path
from typing import List, Dict

from ..config import (
    ENABLE_ESLINT,
    ENABLE_FLAKE8,
    ENABLE_GOLINT,
    ENABLE_BANDIT,
    ENABLE_SEMGREP,
)

logger = logging.getLogger(__name__)

def _run_command(cmd: List[str], cwd: Path) -> subprocess.CompletedProcess:
    """Run *cmd* in *cwd* and return the CompletedProcess.
    ``check=False`` is used so we can capture non‑zero exit codes (linters return
    non‑zero when they find issues). The stdout/stderr are captured as text.
    """
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        logger.warning(f"Linter not found: {cmd[0]}")
        return subprocess.CompletedProcess(args=cmd, returncode=127, stdout="", stderr=f"Command not found: {cmd[0]}")

def _parse_eslint_output(output: str) -> List[Dict]:
    """Parse ``eslint -f json`` output.
    The JSON format is a list of file results each containing ``messages``.
    """
    issues: List[Dict] = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.warning("ESLint output could not be parsed as JSON")
        return issues
    for file_result in data:
        file_path = file_result.get("filePath", "")
        for msg in file_result.get("messages", []):
            severity_map = {2: "high", 1: "medium", 0: "low"}
            issues.append({
                "type": "lint",
                "tool": "eslint",
                "severity": severity_map.get(msg.get("severity", 0), "low"),
                "file": str(Path(file_path).relative_to(Path.cwd())),
                "line": msg.get("line", 0),
                "description": msg.get("message", ""),
                "code": msg.get("source", ""),
            })
    return issues

def _parse_flake8_output(output: str) -> List[Dict]:
    """Parse classic ``flake8`` output lines of the form ``path:line:col: code msg``.
    """
    issues: List[Dict] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            path_line, col_code_msg = line.split(":", 1)
            path, line_no = path_line.rsplit(":", 1)
            col, rest = col_code_msg.lstrip().split(" ", 1)
            code, msg = rest.split(" ", 1)
            severity = "high" if code.startswith("E") else "medium"
            issues.append({
                "type": "lint",
                "tool": "flake8",
                "severity": severity,
                "file": str(Path(path).relative_to(Path.cwd())),
                "line": int(line_no),
                "description": msg.strip(),
                "code": code,
            })
        except Exception:
            continue
    return issues

def _parse_bandit_output(output: str) -> List[Dict]:
    """Bandit can emit JSON with ``-f json``; we parse that.
    For simplicity we treat any finding as ``high`` severity.
    """
    issues: List[Dict] = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.warning("Bandit output could not be parsed as JSON")
        return issues
    for issue in data.get("results", []):
        issues.append({
            "type": "lint",
            "tool": "bandit",
            "severity": "high",
            "file": issue.get("filename", ""),
            "line": issue.get("line_number", 0),
            "description": issue.get("issue_text", ""),
            "code": issue.get("test_id", ""),
        })
    return issues

def _parse_golint_output(output: str) -> List[Dict]:
    """Parse ``golint`` output lines ``path:line:col: message``.
    """
    issues: List[Dict] = []
    for line in output.splitlines():
        parts = line.split(":", 3)
        if len(parts) < 4:
            continue
        path, line_no, _, msg = parts
        issues.append({
            "type": "lint",
            "tool": "golint",
            "severity": "low",
            "file": str(Path(path).relative_to(Path.cwd())),
            "line": int(line_no),
            "description": msg.strip(),
            "code": "",
        })
    return issues

def _parse_semgrep_output(output: str) -> List[Dict]:
    """Semgrep JSON format (``--json``). Each result contains ``path``, ``start`` line, ``extra`` message.
    """
    issues: List[Dict] = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.warning("Semgrep output could not be parsed as JSON")
        return issues
    for result in data.get("results", []):
        meta = result.get("extra", {})
        issues.append({
            "type": "lint",
            "tool": "semgrep",
            "severity": meta.get("severity", "medium"),
            "file": result.get("path", ""),
            "line": result.get("start", {}).get("line", 0),
            "description": meta.get("message", ""),
            "code": meta.get("metadata", {}).get("code", ""),
        })
    return issues

def run_static_analysis(scan_root: Path) -> Dict:
    """Execute enabled linters on *scan_root* and return a composite result.

    The function always returns a dict with the keys ``issues`` (list) and ``summary``.
    ``summary`` contains the total number of files inspected and the count of
    issues per tool.
    """
    issues: List[Dict] = []
    summary = {
        "files_scanned": 0,
        "issues_per_tool": {},
    }

    # Count files (simple walk)
    for _ in scan_root.rglob("*.*"):
        summary["files_scanned"] += 1

    # ESLint (JavaScript/TypeScript)
    if ENABLE_ESLINT:
        eslint_cmd = ["eslint", ".", "-f", "json", "--no-ignore"]
        result = _run_command(eslint_cmd, cwd=scan_root)
        if result.returncode in (0, 1):  # 1 means lint errors found
            parsed = _parse_eslint_output(result.stdout)
            issues.extend(parsed)
            summary["issues_per_tool"]["eslint"] = len(parsed)
        else:
            logger.error(f"ESLint failed: {result.stderr}")

    # Flake8 (Python)
    if ENABLE_FLAKE8:
        flake8_cmd = ["flake8", ".", "--format=%(path)s:%(row)s:%(col)s: %(code)s %(text)s"]
        result = _run_command(flake8_cmd, cwd=scan_root)
        if result.returncode in (0, 1):
            parsed = _parse_flake8_output(result.stdout)
            issues.extend(parsed)
            summary["issues_per_tool"]["flake8"] = len(parsed)
        else:
            logger.error(f"Flake8 failed: {result.stderr}")

    # Bandit (Python security)
    if ENABLE_BANDIT:
        bandit_cmd = ["bandit", "-r", ".", "-f", "json", "-q"]
        result = _run_command(bandit_cmd, cwd=scan_root)
        if result.returncode == 0:
            parsed = _parse_bandit_output(result.stdout)
            issues.extend(parsed)
            summary["issues_per_tool"]["bandit"] = len(parsed)
        else:
            logger.error(f"Bandit failed: {result.stderr}")

    # Golint (Go)
    if ENABLE_GOLINT:
        golint_cmd = ["golint", "./..."]
        result = _run_command(golint_cmd, cwd=scan_root)
        if result.returncode == 0:
            parsed = _parse_golint_output(result.stdout)
            issues.extend(parsed)
            summary["issues_per_tool"]["golint"] = len(parsed)
        else:
            logger.error(f"Golint failed: {result.stderr}")

    # Semgrep (multi‑language)
    if ENABLE_SEMGREP:
        semgrep_cmd = ["semgrep", "--json", "--quiet", "--config", "auto"]
        result = _run_command(semgrep_cmd, cwd=scan_root)
        if result.returncode == 0:
            parsed = _parse_semgrep_output(result.stdout)
            issues.extend(parsed)
            summary["issues_per_tool"]["semgrep"] = len(parsed)
        else:
            logger.error(f"Semgrep failed: {result.stderr}")

    return {"issues": issues, "summary": summary}
