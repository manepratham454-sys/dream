"""SAST orchestrator — analyses uploaded source archives for bugs and
security issues. Mirrors the ``run_scan`` contract from ``zap.py`` so the
``/scans`` endpoint can dispatch file uploads here without any shape change.

In production this orchestrates four layers:
  1. Heuristic patterns (always on, no external deps).
  2. Secret/credential scanner (always on, no external deps).
  3. Bandit (optional subprocess — enabled when installed).
  4. Semgrep (optional subprocess — enabled when installed).

Always returns the same dict shape: ``{"status", "alerts", "source"}``.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

from . import bandit_runner, semgrep_runner, sast_heuristics, secrets_scan

logger = logging.getLogger(__name__)


async def run_scan(target_url: str, source_root: Path) -> Dict[str, Any]:
    """Run SAST over ``source_root``.

    ``target_url`` is the original uploaded filename (kept for parity with
    the ZAP branch); ``source_root`` is the on-disk directory containing the
    extracted source tree.
    """
    alert_groups: list[tuple[str, list[dict]]] = []

    try:
        alert_groups.append(("heuristic", sast_heuristics.scan_path(source_root)))
    except Exception as exc:  # heuristic must NEVER block SAST
        logger.warning("heuristic SAST failed: %s", exc)

    try:
        alert_groups.append(("secrets", secrets_scan.scan_path(source_root)))
    except Exception as exc:
        logger.warning("secrets SAST failed: %s", exc)

    try:
        alert_groups.append(("bandit", bandit_runner.scan_path(source_root)))
    except Exception as exc:
        logger.warning("bandit SAST failed: %s", exc)

    try:
        alert_groups.append(("semgrep", semgrep_runner.scan_path(source_root)))
    except Exception as exc:
        logger.warning("semgrep SAST failed: %s", exc)

    alerts: list[dict] = []
    fired_detectors: list[str] = []
    for name, group in alert_groups:
        if group:
            alerts.extend(group)
            fired_detectors.append(name)

    sources_used = "+".join(fired_detectors) if fired_detectors else "none"
    logger.info("SAST applied to %s: %d finding(s); sources=%s",
                target_url, len(alerts), sources_used)

    return {
        "status": "completed",
        "alerts": alerts,
        # Mark the source distinctly from the ZAP/zap-assisted branches.
        "source": f"sast:{sources_used}",
    }
