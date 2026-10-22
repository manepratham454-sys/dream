from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from ..services import secrets_store

router = APIRouter(prefix="/api/azure", tags=["azure_devops"])

# Provider identifier used in the secrets store
_PROVIDER_ID = "azure_devops"

class AzureConfigRequest(BaseModel):
    organization: str
    project: str
    pipeline_id: int
    pat: str  # Personal Access Token (will be stored encrypted)

@router.post("/config")
async def set_config(cfg: AzureConfigRequest):
    """Save Azure DevOps connection configuration securely.

    The configuration is encrypted using the existing ``secrets_store`` mechanism
    and stored under the ``azure_devops`` provider key.
    """
    if not cfg.pat:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="PAT is required")
    # Store the config as a JSON string so all fields are encrypted together
    payload = json.dumps({
        "organization": cfg.organization,
        "project": cfg.project,
        "pipeline_id": cfg.pipeline_id,
        "pat": cfg.pat,
    })
    secrets_store.set_key(_PROVIDER_ID, payload)
    return {"saved": True, "provider": _PROVIDER_ID}

@router.get("/pipeline_status")
async def pipeline_status():
    """Fetch the latest Azure DevOps pipeline run status.

    Returns a JSON object with ``status``, ``run_id`` and ``result`` fields.
    If the configuration is missing or the request fails, an appropriate HTTP
    error is raised.
    """
    raw = secrets_store.get_key(_PROVIDER_ID)
    if not raw:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Azure DevOps configuration not found")
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Corrupted Azure DevOps config")

    org = cfg["organization"]
    project = cfg["project"]
    pipeline_id = cfg["pipeline_id"]
    pat = cfg["pat"]

    # Azure DevOps uses Basic Auth with empty username and PAT as password
    auth_token = base64.b64encode(f":{pat}".encode()).decode()
    headers = {"Authorization": f"Basic {auth_token}"}
    url = f"https://dev.azure.com/{org}/{project}/_apis/build/builds?definitions={pipeline_id}&api-version=6.0"

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to contact Azure DevOps")
        data = resp.json()
        builds = data.get("value", [])
        if not builds:
            return {"status": "no_runs", "run_id": None, "result": None}
        latest = max(builds, key=lambda b: b.get("queueTime", ""))
        return {
            "status": latest.get("status"),
            "run_id": latest.get("id"),
            "result": latest.get("result"),
        }
