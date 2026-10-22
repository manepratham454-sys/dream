"""AI auto-fix endpoints — generate / review / confirm-then-apply.

Safety model:
  * /fixes/generate and /fixes/regenerate never touch disk — they only
    produce a reviewable FixProposal kept in memory.
  * /fixes/preview-batch returns the EXACT file-changeset without writing.
  * /fixes/apply-batch REFUSES unless body.confirmed is True (defence-in-
    depth around the "never auto-apply without confirmation" rule).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .findings import _lookup_alert
from ..services import apply as apply_svc
from ..services import fix_engine
from ..services.apply import _resolve_safe

logger = logging.getLogger(__name__)

router = APIRouter(tags=["fixes"])

# fix_id -> {proposal, finding, file_contents, provider, ignored}
_fixes: dict[str, dict] = {}
# finding_id -> reason (so we skip re-generating ignored findings)
_ignored: dict[str, str] = {}


class GenerateRequest(BaseModel):
    finding_id: str
    file_contents: Optional[str] = None
    project_root: Optional[str] = None
    provider: Optional[str] = None


class RegenerateRequest(BaseModel):
    fix_id: str
    provider: Optional[str] = None


class BatchRequest(BaseModel):
    fix_ids: list[str]
    project_root: str
    confirmed: bool = False


class IgnoreRequest(BaseModel):
    finding_id: str
    reason: str = ""


def _resolve_file_contents(req: GenerateRequest, finding: dict) -> str:
    """Get the source file text from the request body or from disk."""
    if req.file_contents is not None:
        return req.file_contents
    if req.project_root:
        rel = finding.get("file") or finding.get("url") or ""
        if not rel:
            raise HTTPException(400, "finding has no file path to read from disk")
        try:
            target = _resolve_safe(Path(req.project_root).resolve(), rel)
            return target.read_text("utf-8")
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except OSError as exc:
            raise HTTPException(400, f"could not read {rel}: {exc}") from exc
    raise HTTPException(
        400, "Provide `file_contents` OR `project_root` so the engine has "
             "something to fix.")


@router.post("/fixes/generate")
async def generate_fix(req: GenerateRequest):
    """Generate a reviewable FixProposal for one finding."""
    if req.finding_id in _ignored:
        raise HTTPException(
            409, f"Finding {req.finding_id} is ignored ({_ignored[req.finding_id]})."
        )
    finding = _lookup_alert(req.finding_id)
    if finding is None:
        raise HTTPException(404, f"Finding {req.finding_id} not found")
    file_contents = _resolve_file_contents(req, finding)
    proposal = await fix_engine.generate_fix(
        finding, file_contents, provider=req.provider)
    _fixes[proposal["fix_id"]] = {
        "proposal": proposal,
        "finding": finding,
        "file_contents": file_contents,
        "provider": req.provider or os.getenv("SENTINEL_AI_PROVIDER", "openai"),
    }
    return proposal


@router.post("/fixes/regenerate")
async def regenerate_fix(req: RegenerateRequest):
    """Re-run generation for an existing proposal (new id, same finding)."""
    ctx = _fixes.get(req.fix_id)
    if ctx is None:
        raise HTTPException(404, f"Fix {req.fix_id} not found")
    if ctx["finding"]["id"] in _ignored:
        raise HTTPException(409, "Underlying finding is ignored.")
    finding = ctx["finding"]
    file_contents = ctx["file_contents"]
    proposal = await fix_engine.generate_fix(
        finding, file_contents,
        provider=req.provider or ctx.get("provider"))
    _fixes[proposal["fix_id"]] = {**ctx, "proposal": proposal}
    return proposal


@router.get("/fixes/{fix_id}")
async def get_fix(fix_id: str):
    ctx = _fixes.get(fix_id)
    if ctx is None:
        raise HTTPException(404, f"Fix {fix_id} not found")
    return ctx["proposal"]


def _proposals_for(ids: list[str]) -> list[dict]:
    out: list[dict] = []
    for fid in ids:
        ctx = _fixes.get(fid)
        if ctx is None:
            raise HTTPException(404, f"Fix {fid} not found — generate it first.")
        p = ctx["proposal"]
        if p.get("status") != "ok":
            raise HTTPException(
            409, f"Fix {fid} is not applyable (status={p.get('status')}).")
        out.append(p)
    return out


@router.post("/fixes/preview-batch")
async def preview_batch(req: BatchRequest):
    """Confirm-screen data: exact files/bytes that would change. NO writes."""
    proposals = _proposals_for(req.fix_ids)
    return apply_svc.preview_batch(proposals, req.project_root)


@router.post("/fixes/apply-batch")
async def apply_batch(req: BatchRequest):
    """Write the batch. Refuses unless `confirmed` is True."""
    if not req.confirmed:
        raise HTTPException(
            400, "Refusing to apply: `confirmed` must be true. Call "
                 "/fixes/preview-batch first and have the user approve.")
    proposals = _proposals_for(req.fix_ids)
    return apply_svc.apply_batch(proposals, req.project_root,
                                 confirmed=True)


@router.post("/fixes/ignore")
async def ignore_finding(req: IgnoreRequest):
    """Mark a finding ignored so it won't be re-fixed on future scans."""
    old = _ignored.get(req.finding_id)
    _ignored[req.finding_id] = req.reason or "ignored by user"
    return {"finding_id": req.finding_id,
            "reason": _ignored[req.finding_id],
            "was_ignored": old is not None}


@router.get("/fixes/ignored")
async def list_ignored():
    return [{"finding_id": k, "reason": v} for k, v in _ignored.items()]
