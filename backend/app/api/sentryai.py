"""
SentinelAI API Endpoints (CrowdStrike Charlotte AI SOC Analyst Interface)
Provides REST endpoints for Detection Triage, Telemetry Exploration, Threat Hunting,
Incident Summarization, and Human Authorization Gatekeeper.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel, Field

from ..services.sentry_engine import sentry_engine
from ..services.sentry_telemetry import (
    get_assets,
    get_asset,
    query_cve,
    get_alerts,
    get_alert,
    get_telemetry,
    get_threat_intel,
    get_pending_actions,
    get_all_actions,
    authorize_action,
    get_audit_trail,
    log_audit_event,
)

router = APIRouter(tags=["SentinelAI SOC Analyst"])


# --- PYDANTIC SCHEMAS ---
class ChatRequest(BaseModel):
    message: str = Field(..., description="Analyst natural-language prompt or inquiry")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Optional conversational context")


class TriageRequest(BaseModel):
    alert_id: Optional[str] = Field(None, description="ID of existing alert (e.g. DET-8921)")
    raw_payload: Optional[Dict[str, Any]] = Field(None, description="Custom detection payload from external SIEM/EDR")


class ThreatHuntRequest(BaseModel):
    hypothesis: str = Field(..., description="Analyst hunt hypothesis (e.g. 'Look for lateral movement from FIN-WKS-084')")
    host_filter: Optional[str] = Field(None, description="Optional host ID to constrain hunt scope")


class IncidentSummaryRequest(BaseModel):
    incident_id: str = Field("INC-2026-09", description="Incident ID to compile timeline for")


class AuthorizeActionRequest(BaseModel):
    action_id: str = Field(..., description="Pending action ID (e.g. ACT-701)")
    decision: str = Field(..., description="'approve' or 'reject'")
    analyst_name: str = Field(..., description="Name or email of the authorizing SOC analyst")
    analyst_notes: Optional[str] = Field("", description="Mandatory rationale/audit commentary")


# --- ENDPOINTS ---

@router.post("/chat")
async def sentry_chat(req: ChatRequest):
    """
    Charlotte AI Conversational Interface:
    Processes natural language inquiries, alert triage, threat hunt requests,
    CVE assessments, and incident summaries while adhering to all Hard Rules.
    """
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")
    
    result = sentry_engine.handle_chat_message(req.message, req.context)
    return {
        "status": "success",
        "agent": "SentinelAI (Charlotte Model)",
        "result": result
    }


@router.post("/triage")
async def sentry_triage(req: TriageRequest):
    """
    Autonomous Detection Triage:
    Grounded in actual telemetry (process trees, network sockets, hashes).
    Outputs: Verdict -> Confidence -> Evidence -> Recommended Action -> Requires-Human-Approval.
    """
    if req.alert_id:
        res = sentry_engine.triage_alert(req.alert_id)
    elif req.raw_payload:
        res = sentry_engine.triage_alert(req.raw_payload)
    else:
        raise HTTPException(status_code=400, detail="Must provide either alert_id or raw_payload.")
    
    return {
        "status": "success",
        "triage": res
    }


@router.post("/hunt")
async def sentry_hunt(req: ThreatHuntRequest):
    """
    Threat Hunting Assistant:
    Translates hypothesis into multi-dialect EDR queries (CrowdStrike FQL, Splunk SPL, KQL, Sigma),
    explains logic step-by-step, and executes against the active telemetry store.
    """
    res = sentry_engine.hunt_hypothesis(req.hypothesis, req.host_filter)
    if "error" in res:
        raise HTTPException(status_code=403, detail=res["error"])
    return {
        "status": "success",
        "hunt": res
    }


@router.post("/summarize-incident")
async def sentry_summarize_incident(req: IncidentSummaryRequest):
    """
    Incident Summarization & Timeline Reconstruction:
    Produces executive-readable summaries and technical SOC timelines,
    strictly distinguishing confirmed telemetry facts from analyst inferences.
    """
    res = sentry_engine.summarize_incident(req.incident_id)
    return {
        "status": "success",
        "incident": res
    }


@router.get("/alerts")
async def list_alerts():
    """Returns active SOC detection alerts with telemetry cross-references."""
    alerts = get_alerts()
    return {
        "count": len(alerts),
        "alerts": alerts
    }


@router.get("/alerts/{alert_id}")
async def get_single_alert(alert_id: str):
    """Retrieve details and raw telemetry for a specific detection alert."""
    alert = get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found in available telemetry.")
    telemetry = get_telemetry(host_id=alert.get("host_id"))
    return {
        "alert": alert,
        "related_telemetry": telemetry
    }


@router.get("/telemetry")
async def query_endpoint_telemetry(
    host_id: Optional[str] = Query(None, description="Filter by Host ID (e.g. FIN-WKS-084)"),
    pid: Optional[int] = Query(None, description="Filter by Process ID")
):
    """Retrieve grounded endpoint telemetry (process events, network sockets, hashes, registry)."""
    data = get_telemetry(host_id=host_id, pid=pid)
    return {
        "count": len(data),
        "telemetry": data
    }


@router.get("/assets")
async def list_assets():
    """Retrieve enterprise asset inventory, installed software, and CVE vulnerability status."""
    assets = get_assets()
    return {
        "count": len(assets),
        "assets": assets
    }


@router.get("/assets/cve")
async def query_cve_exposure(cve: str = Query(..., description="CVE identifier (e.g. CVE-2026-3819)")):
    """Assess real asset exposure to a specific CVE. Zero fabrication: returns 0 if not in telemetry."""
    matches = query_cve(cve)
    return {
        "cve_searched": cve.upper(),
        "exposed_count": len(matches),
        "matches": matches,
        "verified_grounded": True
    }


@router.get("/threat-intel")
async def list_threat_intel():
    """Retrieve active Threat Intelligence feeds (IOCs, Threat Actors, C2 infrastructure)."""
    ti = get_threat_intel()
    return {
        "count": len(ti),
        "threat_intel": ti
    }


@router.get("/actions/pending")
async def list_pending_actions():
    """
    Retrieve remediation actions awaiting explicit human confirmation.
    Hard Rule: SentinelAI cannot enact state changes without analyst authorization.
    """
    pending = get_pending_actions()
    all_actions = get_all_actions()
    return {
        "pending_count": len(pending),
        "total_count": len(all_actions),
        "pending_actions": pending,
        "all_actions": all_actions
    }


@router.post("/actions/authorize")
async def authorize_remediation_action(req: AuthorizeActionRequest):
    """
    Human Authorization Gatekeeper:
    Executes or cancels a proposed remediation action upon explicit human confirmation.
    Records mandatory compliance audit trail entry.
    """
    try:
        res = authorize_action(
            action_id=req.action_id,
            decision=req.decision,
            analyst_name=req.analyst_name,
            analyst_notes=req.analyst_notes or "Authorized via SOC SentinelAI Console."
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/audit-log")
async def get_compliance_audit_log():
    """
    Returns the immutable SOC audit trail for compliance, forensic review,
    and post-incident analysis.
    """
    trail = get_audit_trail()
    return {
        "count": len(trail),
        "audit_trail": trail
    }
