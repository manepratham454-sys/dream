"""OWASP ZAP integration with a demo-fallback so the UI always works."""
import asyncio
import logging
import os
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
ZAP_ENABLED = os.getenv("ZAP_ENABLED", "false").lower() in ("1", "true", "yes")


def _add_apikey(params: Dict[str, Any]) -> Dict[str, Any]:
    if ZAP_API_KEY:
        params["apikey"] = ZAP_API_KEY
    return params


# Curated, realistic findings used when no live ZAP is configured.
_MOCK_ALERTS = [
    {
        "id": 1, "pluginid": "40018", "name": "SQL Injection",
        "risk": "high", "confidence": "medium",
        "cweid": "89", "owasp": "A03:2021 - Injection",
        "url": "/api/login", "param": "username", "evidence": "' OR '1'='1",
        "description": "User-supplied input is concatenated into a SQL query.",
        "solution": "Use parameterised queries / prepared statements; deny raw concatenation.",
    },
    {
        "id": 2, "pluginid": "10038", "name": "Cross Site Scripting (Reflected)",
        "risk": "medium", "confidence": "high",
        "cweid": "79", "owasp": "A03:2021 - Injection",
        "url": "/search", "param": "q", "evidence": "<script>alert(1)</script>",
        "description": "Input reflected without contextual output encoding.",
        "solution": "HTML-encode user input; apply a strict Content-Security-Policy.",
    },
    {
        "id": 3, "pluginid": "10202", "name": "Anti-CSRF Tokens Missing",
        "risk": "medium", "confidence": "medium",
        "cweid": "352", "owasp": "A01:2021 - Broken Access Control",
        "url": "/account/update", "param": "", "evidence": "No CSRF token in form",
        "description": "State-changing request performs no CSRF token check.",
        "solution": "Issue + verify synchroniser anti-CSRF tokens on every state change.",
    },
    {
        "id": 4, "pluginid": "10027", "name": "Content Security Policy (CSP) Missing",
        "risk": "low", "confidence": "high",
        "cweid": "1021", "owasp": "A05:2021 - Security Misconfiguration",
        "url": "/", "param": "", "evidence": "No Content-Security-Policy header",
        "description": "No CSP header returned by the application.",
        "solution": "Add a strict Content-Security-Policy response header.",
    },
    {
        "id": 5, "pluginid": "10098", "name": "Cookie Without Secure Flag",
        "risk": "low", "confidence": "high",
        "cweid": "614", "owasp": "A05:2021 - Security Misconfiguration",
        "url": "/", "param": "session", "evidence": "Set-Cookie: session=...; HttpOnly",
        "description": "Session cookie set without the Secure attribute.",
        "solution": "Set the Secure flag on all session cookies; serve over HTTPS only.",
    },
]


async def _live_zap_scan(target_url: str) -> Dict[str, Any]:
    async with httpx.AsyncClient() as client:
        spider = await client.get(
            f"{ZAP_API_URL}/JSON/spider/action/scan",
            params=_add_apikey({"url": target_url}), timeout=30,
        )
        spider.raise_for_status()
        spider_id = spider.json().get("scan")
        while True:
            r = await client.get(
                f"{ZAP_API_URL}/JSON/spider/view/status",
                params=_add_apikey({"scanId": spider_id}),
            )
            r.raise_for_status()
            if int(r.json().get("status", 0)) >= 100:
                break
            await asyncio.sleep(2)

        active = await client.get(
            f"{ZAP_API_URL}/JSON/ascan/action/scan",
            params=_add_apikey({"url": target_url}), timeout=30,
        )
        active.raise_for_status()
        active_id = active.json().get("scan")
        while True:
            r = await client.get(
                f"{ZAP_API_URL}/JSON/ascan/view/status",
                params=_add_apikey({"scanId": active_id}),
            )
            r.raise_for_status()
            if int(r.json().get("status", 0)) >= 100:
                break
            await asyncio.sleep(5)

        alerts = await client.get(
            f"{ZAP_API_URL}/JSON/alert/view/alerts",
            params=_add_apikey({"baseurl": target_url}),
        )
        alerts.raise_for_status()
        return {
            "status": "completed",
            "alerts": alerts.json().get("alerts", []),
            "source": "zap",
        }


async def run_scan(target_url: str) -> Dict[str, Any]:
    """Run a scan against ``target_url``.

    * With ``ZAP_ENABLED=true`` and a reachable ZAP API -> real ZAP scan.
    * Otherwise -> curated mock findings so the Sentinel UI is always alive.
    """
    if not ZAP_ENABLED:
        # Tiny artificial delay so the "live scan" animation feels real.
        await asyncio.sleep(1.2)
        return {"status": "completed", "alerts": _MOCK_ALERTS, "source": "demo"}

    try:
        return await _live_zap_scan(target_url)
    except Exception as exc:
        logger.warning("ZAP scan failed (%s); falling back to demo alerts", exc)
        return {
            "status": "completed",
            "alerts": _MOCK_ALERTS,
            "source": "demo-fallback",
            "error": str(exc),
        }


# Backwards-compatible alias used by older imports.
async def run_zap_scan(target_url: str) -> Dict[str, Any]:
    return await run_scan(target_url)
