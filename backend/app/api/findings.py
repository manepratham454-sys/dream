"""Findings endpoints (read alerts stored from a scan)."""
from fastapi import APIRouter, HTTPException

from .scan import scans

router = APIRouter(tags=["findings"])


def _lookup_alert(finding_id: str) -> dict | None:
    """Find an alert by its numeric id (string-compared) or `pluginid`."""
    for scan in scans.values():
        for alert in scan.get("alerts", []):
            if str(alert.get("id")) == finding_id or alert.get("pluginid") == finding_id:
                return alert
    return None


@router.get("/scans/{scan_id}/findings")
async def list_findings(scan_id: str):
    """Return the alert list for a given scan id."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id].get("alerts", [])


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    """Lookup a single finding across all scans by its id field."""
    alert = _lookup_alert(finding_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return alert


@router.get("/findings/{finding_id}/explanation")
async def explain_finding(finding_id: str):
    """Plain-language explanation + remediation for a finding.

    Falls back to a generic phrasing when the finding lacks its own
    ``description``/``solution`` (e.g. legacy ZAP-shaped alerts), but
    surfaces the SAST-specific remediation text verbatim when present.
    """
    alert = _lookup_alert(finding_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    name = alert.get("name", "Unknown threat")
    risk = (alert.get("risk") or "medium").lower()
    description = alert.get("description")
    remediation = alert.get("solution")

    if description or remediation:
        plain_text = description or (
            f"{name} was detected in the scanned source or running "
            f"application. Severity rating: {risk}."
        )
        attack_path = (
            f"Source: {alert.get('source', 'unknown')}\n"
            f"Location: {alert.get('url') or alert.get('file', 'n/a')}"
            + (f":{alert.get('line')}" if alert.get("line") else "")
            + (f"\nCWE-{alert.get('cwe')}: {alert.get('owasp', '')}"
               if alert.get("cwe") else "")
        )
        return {
            "finding_id": finding_id,
            "plain_text": plain_text,
            "attack_path": attack_path,
            "remediation": remediation or (
                "Apply the contextual best-practice fix for "
                f"CWE-{alert.get('cwe', 'n/a')}; add a regression test and "
                "re-scan with Sentinel to confirm closure."
            ),
        }

    # Legacy fallback for alerts with no per-finding text (mock / live ZAP).
    return {
        "finding_id": finding_id,
        "plain_text": (
            f"{name} lets an attacker tamper with request data in ways the "
            "application does not validate. With a "
            + risk
            + "-severity impact this weakens the perimeter of your outpost "
            "and may expose user data."
        ),
        "attack_path": (
            "1. Attacker probes input parameters.\n"
            "2. Payload reflected/stored without sanitisation.\n"
            "3. Execution or data leak on the victim session."
        ),
        "remediation": (
            "1. Validate + parameterise all inputs server-side.\n"
            "2. Apply contextual output encoding.\n"
            "3. Add regression tests; re-scan with Sentinel to confirm closure."
        ),
    }

