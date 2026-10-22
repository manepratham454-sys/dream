"""Settings endpoints — AI provider + API key management (spec screen #2).

Safety model:
  * Keys are set via POST, stored encrypted-at-rest by ``secrets_store``.
  * Keys are NEVER returned to the UI (verified by listing only provider
    names, never the secret value). The only facts exposed per provider are:
    has a key? which model's selected? is encryption real or obfuscated?
  * ``/settings/test`` validates a key by making ONE lightweight authenticated
    call (OpenAI/Ollama: list models; Anthropic: a 1-token message) and
    returns pass/fail + latency — never logging the key.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..services import secrets_store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["settings"])

# Per-provider model picker. One-line notes explain the cost/speed tradeoff,
# exactly as the spec asks ("cost/speed tradeoff explained in one line each").
_PROVIDERS_META: list[dict] = [
    {
        "id": "openai",
        "label": "OpenAI",
        "needs_key": True,
        "default_model": "gpt-4o-mini",
        "models": [
            {"id": "gpt-4o", "label": "GPT-4o",
             "note": "Strongest reasoning; higher cost per call."},
            {"id": "gpt-4o-mini", "label": "GPT-4o mini",
             "note": "Fast + cheap; good default for most fixes."},
        ],
    },
    {
        "id": "anthropic",
        "label": "Anthropic (Claude)",
        "needs_key": True,
        "default_model": "claude-3-5-sonnet-20241022",
        "models": [
            {"id": "claude-3-5-sonnet-20241022", "label": "Claude 3.5 Sonnet",
             "note": "Excellent at code + security diffs; mid-tier cost."},
            {"id": "claude-3-5-haiku-20241022", "label": "Claude 3.5 Haiku",
             "note": "Fastest + cheapest Claude; lighter reasoning."},
        ],
    },
    {
        "id": "ollama",
        "label": "Local model (Ollama)",
        "needs_key": False,
        "default_model": "qwen2.5-coder:7b",
        "models": [
            {"id": "qwen2.5-coder:7b", "label": "Qwen2.5 Coder 7B",
             "note": "Runs locally; nothing leaves the machine."},
            {"id": "llama3.1:8b", "label": "Llama 3.1 8B",
             "note": "General local model; free, offline."},
        ],
    },
]
_PROVIDERS_BY_ID = {p["id"]: p for p in _PROVIDERS_META}

# Models aren't secret — plain JSON next to the encrypted key store.
_MODELS_FILE = Path(
    os.getenv("SENTINEL_HOME", str(Path.home() / ".sentinel"))) / "models.json"


def _read_models() -> dict:
    if not _MODELS_FILE.is_file():
        return {}
    try:
        return json.loads(_MODELS_FILE.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_models(data: dict) -> None:
    _MODELS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _MODELS_FILE.write_text(json.dumps(data, indent=2), "utf-8")


class KeyRequest(BaseModel):
    provider: str
    api_key: str
    model: Optional[str] = None


class TestRequest(BaseModel):
    provider: str
    model: Optional[str] = None
    # Optional: test a just-pasted key BEFORE saving it. When omitted, the
    # provider's stored key (if any) is used.
    api_key: Optional[str] = None


@router.get("/settings/status")
async def status():
    """Provider/key overview. NEVER returns any secret material."""
    configured = secrets_store.list_providers()
    models = _read_models()
    return {
        "providers_configured": configured,
        "has_any_key": bool(configured),
        "active_provider": os.getenv("SENTINEL_AI_PROVIDER", "openai"),
        "cryptography_available": secrets_store._have_cryptography(),
        "providers": [
            {
                **p,
                "has_key": p["id"] in configured,
                "selected_model": models.get(p["id"]) or p["default_model"],
            }
            for p in _PROVIDERS_META
        ],
    }


@router.post("/settings/key")
async def set_key(req: KeyRequest):
    """Save (or rotate) a provider's API key + optional default model."""
    if req.provider.lower() not in _PROVIDERS_BY_ID:
        raise HTTPException(400, f"unknown provider: {req.provider}")
    if _PROVIDERS_BY_ID[req.provider.lower()]["needs_key"] and not req.api_key:
        raise HTTPException(400, "api_key is required for this provider")
    secrets_store.set_key(req.provider, req.api_key)
    if req.model:
        models = _read_models()
        models[req.provider.lower()] = req.model
        _write_models(models)
    return {
        "provider": req.provider.lower(),
        "saved": True,
        "model": _read_models().get(req.provider.lower()),
        "needs_key": _PROVIDERS_BY_ID[req.provider.lower()]["needs_key"],
    }


@router.delete("/settings/key/{provider}")
async def delete_key(provider: str):
    removed = secrets_store.delete_key(provider)
    if not removed:
        raise HTTPException(404, f"no key stored for {provider}")
    return {"provider": provider.lower(), "deleted": True}


async def _test_one(provider: str, api_key: str | None,
                     model: str | None) -> tuple[bool, str]:
    """Make ONE lightweight authenticated call. Never logs the key.

    Returns (ok, human-readable detail). Used by /settings/test.
    """
    pid = provider.lower()
    t0 = time.perf_counter()
    try:
        if pid == "openai":
            from openai import AsyncOpenAI
            client = AsyncOpenAI(api_key=api_key or "")
            await client.models.list()
        elif pid == "ollama":
            import httpx
            base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(f"{base}/api/tags")
                r.raise_for_status()
        elif pid == "anthropic":
            import httpx
            headers = {"x-api-key": api_key or "",
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json"}
            body = {"model": model or "claude-3-5-sonnet-20241022",
                    "max_tokens": 1, "messages": [{"role": "user",
                    "content": "ping"}]}
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.post("https://api.anthropic.com/v1/messages",
                                json=body, headers=headers)
                r.raise_for_status()
        else:
            return False, f"unknown provider: {provider}"
    except Exception as exc:  # noqa: BLE001 — surface any failure reason
        ms = int((time.perf_counter() - t0) * 1000)
        return False, f"{type(exc).__name__}: {exc}"[:200] + f" ({ms}ms)"
    ms = int((time.perf_counter() - t0) * 1000)
    return True, f"connection ok ({ms}ms)"


@router.post("/settings/test")
async def test_connection(req: TestRequest):
    """Validate a key. Uses the stored key unless an ``api_key`` is supplied
    in the request (lets the UI test a pasted key before saving)."""
    pid = req.provider.lower()
    if pid not in _PROVIDERS_BY_ID:
        raise HTTPException(400, f"unknown provider: {req.provider}")
    api_key = req.api_key if hasattr(req, "api_key") else None
    if api_key is None:
        api_key = secrets_store.get_key(pid)
    ok, detail = await _test_one(pid, api_key, req.model)
    return {"provider": pid, "ok": ok, "detail": detail}

