"""Dependency-free secret/credential scanner.

Catches hard-coded secrets, accidental `.env` uploads, AWS / GCP / GitHub /
Slack keys, JWTs, and PEM private keys via curated regex patterns. Always runs
— no external tool required — so uploaded source always yields *some* real
findings even when semgrep/bandit are not installed.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# Each rule: (id, name, severity, cwe, pattern, message, solution)
# Patterns are deliberately tuned for low false-positive rate (high specificity)
# rather than recall — we want the showcased findings to look genuinely scary.
_RULES: list[tuple] = [
    (
        "sentinel:secret.aws_access_key_id",
        "Hard-coded AWS Access Key ID",
        "high",
        "798",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "An AWS access key id was committed in source. Anyone with repository "
        "access can impersonate this IAM principal.",
        "Rotate the key immediately, move it to a secret manager / env var, "
        "and force-scrub it from git history (e.g. `git filter-repo`).",
    ),
    (
        "sentinel:secret.aws_secret",
        "Hard-coded AWS Secret Access Key",
        "high",
        "798",
        # typical 40-char base64-ish secret, only flag obvious assignments
        re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
        "An AWS secret access key is assigned to a literal string in source.",
        "Rotate the key, never commit secrets — load from the environment or "
        "a secrets manager (AWS SSM, Vault, Doppler, etc.).",
    ),
    (
        "sentinel:secret.github_pat",
        "Hard-coded GitHub Personal Access Token",
        "high",
        "798",
        re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
        "A GitHub personal access token is hard-coded in source.",
        "Revoke the token, use the `GITHUB_TOKEN` action secret or an env var "
        "injected at deploy time instead.",
    ),
    (
        "sentinel:secret.google_api",
        "Hard-coded Google API Key",
        "high",
        "798",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "A Google API key is hard-coded in source.",
        "Restrict the key by IP / referer in the Google Cloud console, rotate "
        "it, and load it from a secret store.",
    ),
    (
        "sentinel:secret.slack_token",
        "Hard-coded Slack Token",
        "high",
        "798",
        re.compile(r"\bxox[abp]-[0-9A-Za-z-]{10,72}\b"),
        "A Slack API token is hard-coded in source.",
        "Revoke the token in the Slack admin dashboard and load it from the "
        "environment instead.",
    ),
    (
        "sentinel:secret.jwt",
        "Hard-coded JWT in source",
        "medium",
        "798",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        "A JSON Web Token is committed in source or used as a static string.",
        "Generate JWTs at runtime from a secret with a short TTL; never commit "
        "a bearer token to a repo.",
    ),
    (
        "sentinel:secret.private_key",
        "Committed Private Key (PEM)",
        "high",
        "321",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "A PEM-encoded private key is present in the repository.",
        "Revoke the key, rotate any credential it protected, and remove it "
        "from git history using `git filter-repo` / BFG.",
    ),
    (
        "sentinel:secret.generic_assign",
        "Hard-coded Credential Assignment",
        "medium",
        "798",
        re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*"
            r"['\"][^'\"\s]{8,}['\"]"
        ),
        "A credential-like variable is assigned a non-empty literal string.",
        "Avoid hard-coding credentials; load sensitive values from environment "
        "variables or a dedicated secrets manager.",
    ),
    (
        "sentinel:secret.dotenv_body",
        "Hard-coded secret inside `.env` file",
        "high",
        "540",
        re.compile(r"^[A-Z][A-Z0-9_]*=(?!$|your_|xxx|change_me|example)[^\n]*$", re.M),
        "A KEY=VALUE pair in an environment file looks like a real secret "
        "rather than a placeholder.",
        "Add `.env` to `.gitignore`; never deploy a `.env` file. Load real "
        "secrets from the runtime environment.",
    ),
]

# Files whose mere presence is suspicious — commit-hygiene findings.
_SUSPECT_FILENAMES: dict[str, tuple] = {
    ".env": ("sentinel:secret.env_present", "Committed `.env` file",
             "high", "540"),
    ".env.local": ("sentinel:secret.env_local_present",
                   "Committed `.env.local` file", "high", "540"),
    "id_rsa": ("sentinel:secret.ssh_private_present",
               "Committed SSH private key (`id_rsa`)", "high", "321"),
    ".npmrc": ("sentinel:secret.npmrc_present",
               "Committed `.npmrc` (may hold npm authToken)", "medium", "798"),
    ".pypirc": ("sentinel:secret.pypirc_present",
                "Committed `.pypirc` (may hold PyPI token)", "medium", "798"),
}


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _iter_files(root: Path) -> Iterator[Path]:
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv",
                 "dist", "build", ".next", ".cache"}
    for p in root.rglob("*"):
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.is_file() and p.stat().st_size < 5 * 1024 * 1024:  # 5 MB cap
            yield p


def _stable_id(rule_id: str, file: str, line: int) -> str:
    import hashlib
    h = hashlib.sha1(f"{rule_id}|{file}|{line}".encode()).hexdigest()
    # Numeric id string for backwards-compat with findings.py's
    # `str(alert.get("id"))` lookup.
    return str(int(h[:12], 16))


def _solution_for_secret() -> str:
    return (
        "Rotate the exposed credential immediately, move it to a secret "
        "manager or environment variable injected at runtime, add the "
        "offending path to `.gitignore`, and scrub it from repository history."
    )


def _finding(*, rule_id: str, title: str, severity: str, cwe: str,
             file: str, line: int, excerpt: str, description: str,
             solution: str) -> dict:
    return {
        "id": _stable_id(rule_id, file, line),
        "pluginid": rule_id,
        "name": title,
        "risk": severity,
        "confidence": "high",
        "cwe": cwe,
        "cweid": cwe,
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "url": f"{file}:{line}",
        "file": file,
        "line": line,
        "param": "",
        "evidence": excerpt,
        "description": description,
        "solution": solution,
        "source": "sast:secrets",
    }


def scan_path(root: Path) -> list[dict]:
    """Return a list of secret/credential findings under ``root``."""
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()

    for path in _iter_files(root):
        rel = path.relative_to(root).as_posix()
        name = path.name

        # 1) Suspicious filename rule (catches committed .env / id_rsa).
        if name in _SUSPECT_FILENAMES:
            rid, title, sev, cwe = _SUSPECT_FILENAMES[name]
            findings.append(_finding(
                rule_id=rid, title=title, severity=sev, cwe=cwe,
                file=rel, line=1,
                excerpt=f"{name} present in source tree",
                description=f"The file `{name}` was uploaded inside the "
                            f"source archive, which is a common source of "
                            f"leaked secrets.",
                solution=_solution_for_secret(),
            ))

        # 2) Read content + run regex rules. Skip binaries.
        try:
            raw = path.read_bytes()
            if b"\x00" in raw[:2048]:
                continue
            text = raw.decode("utf-8", errors="ignore")
        except OSError:
            continue

        # 2a) .env file body scan uses the special multi-line rule.
        if name.startswith(".env") or name.endswith(".env"):
            for m in _RULES[-1][3].finditer(text):
                key = ("sentinel:secret.dotenv_body", _line_of(text, m.start()))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_finding(
                    rule_id="sentinel:secret.dotenv_body",
                    title="Hard-coded secret inside `.env` file",
                    severity="high",
                    cwe="540",
                    file=rel,
                    line=_line_of(text, m.start()),
                    excerpt=m.group(0).strip()[:120],
                    description=_RULES[-1][5],
                    solution=_RULES[-1][6],
                ))

        # 2b) Generic regex rules (skip the .env body rule, handled above).
        for rule in _RULES[:-1]:
            rule_id, title, sev, cwe, pattern = rule[0], rule[1], rule[2], rule[3], rule[4]
            for m in pattern.finditer(text):
                line = _line_of(text, m.start())
                key = (rule_id, line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_finding(
                    rule_id=rule_id, title=title, severity=sev, cwe=cwe,
                    file=rel, line=line, excerpt=m.group(0)[:120],
                    description=rule[5], solution=rule[6],
                ))

    logger.info("secrets scan: %d finding(s) under %s", len(findings), root)
    return findings

