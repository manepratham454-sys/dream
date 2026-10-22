"""AI auto-fix engine.

Given a SAST finding + the file's current contents, asks a pluggable AI
provider (OpenAI / Anthropic / local Ollama) to return a strict-JSON
``FixProposal`` containing an explanation + a unified-style diff + the
full edited file. On any failure (no key, network error, bad JSON, parse
error) we fall back to a deterministic local patch built from the SAST
rule's own ``solution`` text — so the API is ALWAYS useful, even offline.

Public API:
    generate_fix(finding, file_contents, *, provider=None, model=None)

Returns a dict shaped like::

    {
      "fix_id": "<uuid>",
      "status": "ok" | "skipped" | "error",
      "reason": "<only when not ok>",
      "explanation": str,
      "diff": [{op, old_start, old_lines, new_lines}],
      "edited_full_file": str,
    }
"""
from __future__ import annotations

import json
import logging
import os
import re
import uuid
from typing import Any, Optional

from . import secrets_store

logger = logging.getLogger(__name__)

MAX_FIX_FILE_BYTES = int(os.getenv("SENTINEL_MAX_FIX_FILE_BYTES", "262144"))

# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------
class BaseProvider:
    """Pluggable AI-provider interface."""

    name: str = "base"

    def __init__(self, api_key: str | None, model: str | None):
        self.api_key = api_key
        self.model = model

    async def complete(self, system: str, user: str,
                       temperature: float = 0.2) -> str:
        raise NotImplementedError


class OpenAIProvider(BaseProvider):
    name = "openai"

    async def complete(self, system, user, temperature=0.2):
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=self.api_key)
        resp = await client.chat.completions.create(
            model=self.model or "gpt-4o-mini",
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={"type": "json_object"},
        )
        return resp.choices[0].message.content or ""


class OllamaProvider(BaseProvider):
    """Local Ollama — OpenAI-compatible /v1/chat/completions endpoint."""

    name = "ollama"

    async def complete(self, system, user, temperature=0.2):
        from openai import AsyncOpenAI
        client = AsyncOpenAI(
            api_key=self.api_key or "ollama",
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        )
        resp = await client.chat.completions.create(
            model=self.model or "qwen2.5-coder:7b",
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""


class AnthropicProvider(BaseProvider):
    """Anthropic via raw httpx (no SDK dependency)."""

    name = "anthropic"

    async def complete(self, system, user, temperature=0.2):
        import httpx
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key or "",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": self.model or "claude-3-5-sonnet-20241022",
            "max_tokens": 4096,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(url, json=body, headers=headers)
            r.raise_for_status()
            data = r.json()
        # content is a list of {type:"text", text:"..."} blocks
        parts = data.get("content", [])
        return "".join(p.get("text", "") for p in parts
                       if p.get("type") == "text")


_PROVIDERS = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
}


def get_provider(name: str) -> BaseProvider:
    """Build a provider instance, reading key + default model from env."""
    cls = _PROVIDERS.get(name.lower())
    if cls is None:
        raise ValueError(f"unknown provider {name!r}")
    key = secrets_store.get_key(name) or os.getenv(
        {"openai": "OPENAI_API_KEY",
         "anthropic": "ANTHROPIC_API_KEY",
         "ollama": "OLLAMA_API_KEY"}.get(name.lower(), "")
    )
    model = os.getenv({
        "openai": "OPENAI_MODEL",
        "anthropic": "ANTHROPIC_MODEL",
        "ollama": "OLLAMA_MODEL",
    }.get(name.lower(), ""))
    return cls(key, model or None)


# ---------------------------------------------------------------------------
# Prompt + JSON schema
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = (
    "You are Sentinel-Forge, an expert security-focused code-fixer. "
    "Given a single SAST/bug finding and the file's current contents, "
    "produce the MINIMAL correct fix. Return STRICT JSON only — no prose, "
    "no markdown fences. The JSON MUST match this schema:\n"
    "{\n"
    "  \"explanation\": string,   // one short paragraph: what + why\n"
    "  \"diff\": [                 // ordered list of edits\n"
    "    {\"op\": \"replace\",\n"
    "     \"old_start\": 1-based line number,\n"
    "     \"old_lines\": [original lines],\n"
    "     \"new_lines\": [replacement lines]}\n"
    "  ],\n"
    "  \"edited_full_file\": string // the FULL file text after the fix\n"
    "}\n"
    "Rules:\n"
    " - Only fix the reported issue. Do NOT reformat unrelated lines.\n"
    " - Preserve indentation and existing style.\n"
    " - If the file should NOT be edited (e.g. a config flag rotation), "
    "return `edited_full_file` identical to the input and an empty diff.\n"
)

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _strip_fences(s: str) -> str:
    """Remove stray ```json ... ``` fences some models add despite the rules."""
    return _JSON_FENCE_RE.sub("", s).strip()


def _parse_response(raw: str) -> dict:
    """Parse a model's raw reply into the fix dict; raise on bad JSON."""
    cleaned = _strip_fences(raw)
    # Some providers wrap JSON in a preamble; find the first { ... } block.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in model reply")
    obj = json.loads(cleaned[start:end + 1])
    if "edited_full_file" not in obj:
        raise ValueError("missing 'edited_full_file'")
    obj.setdefault("diff", [])
    obj.setdefault("explanation", "")
    return obj


# ---------------------------------------------------------------------------
# Deterministic local fallback — used when no provider is configured, the
# API call fails, or the model returns unparseable JSON. So the engine is
# ALWAYS useful, even offline.
# ---------------------------------------------------------------------------
def _local_substitute(finding: dict, src: str) -> Optional[dict]:
    """Return a fix dict for findings whose `pluginid` we recognise.

    Returns None for findings we don't have a deterministic patch for —
    caller then returns a 'no fix available offline' status.
    """
    rule = (finding.get("pluginid") or "").lower()
    # eval()  ->  ast.literal_eval
    if rule.endswith(".eval") and "eval(" in src:
        new = src.replace("eval(", "ast.literal_eval(", 1)
        # naive import insertion if ast not already imported
        if "import ast" not in src:
            new = "import ast\n" + new
        return {
            "explanation": (
                "Replaced `eval(...)` with `ast.literal_eval(...)` which "
                "only accepts Python literals and cannot execute arbitrary "
                "code. (Generated offline by Sentinel's deterministic "
                "fallback, because no AI provider was available.)"
            ),
            "diff": [{
                "op": "replace",
                "old_start": (finding.get("line") or 0),
                "old_lines": ["eval("],
                "new_lines": ["ast.literal_eval("],
            }],
            "edited_full_file": new,
        }
    # shell=True  ->  drop it (caller must validate args separately; we
    # only flag, we don't silently change control flow).
    return None


def _skipped(reason: str) -> dict:
    return {"fix_id": str(uuid.uuid4()), "status": "skipped",
            "reason": reason, "explanation": "", "diff": [],
            "edited_full_file": ""}


def _user_prompt(finding: dict, src: str) -> str:
    """Build the per-finding user message — minimal tokens, full context."""
    return json.dumps({
        "finding": {
            "name": finding.get("name", ""),
            "risk": finding.get("risk", ""),
            "cwe": finding.get("cwe", ""),
            "owasp": finding.get("owasp", ""),
            "file": finding.get("file", ""),
            "line": finding.get("line", ""),
            "evidence": (finding.get("evidence") or "")[:300],
            "description": (finding.get("description") or "")[:600],
            "solution": (finding.get("solution") or "")[:600],
            "source": finding.get("source", ""),
        },
        "file_contents": src,
    }, indent=2)


async def generate_fix(finding: dict, file_contents: str, *,
                      provider: str | None = None) -> dict:
    """Generate a FixProposal for one finding.

    Safety rails (enforced here, not just in the UI):
      * Reject files matching secret patterns — these must NEVER leave
        the machine.
      * Reject oversized files (> MAX_FIX_FILE_BYTES).
      * Never let an AI exception crash the endpoint — fall back.
    """
    # --- guards --------------------------------------------------------------
    fpath = finding.get("file") or finding.get("url") or ""
    if secrets_store.looks_like_secret_file(fpath):
        return _skipped(
            f"secret-like file ({fpath}) excluded from AI review per "
            "sentinel safety policy. Fix manually with secret rotation."
        )
    if len(file_contents.encode("utf-8")) > MAX_FIX_FILE_BYTES:
        return _skipped(
            f"file exceeds {MAX_FIX_FILE_BYTES} byte cap; chunk or fix "
            "manually before invoking the AI engine."
        )

    provider_name = (provider or os.getenv("SENTINEL_AI_PROVIDER", "openai")).lower()

    # --- AI attempt (with one JSON-nudge retry) ------------------------------
    try:
        prov = get_provider(provider_name)
        if prov.api_key or provider_name == "ollama":
            user = _user_prompt(finding, file_contents)
            raw = await prov.complete(_SYSTEM_PROMPT, user)
            try:
                obj = _parse_response(raw)
            except Exception as bad:
                logger.warning("first reply not JSON (%s); nudging", bad)
                nudge = ("Your previous reply was not valid JSON. Reply "
                         "with STRICT JSON only — no markdown fences, no "
                         "preamble. Schema: " + json.dumps({
                             "explanation": "string",
                             "diff": [{"op": "replace",
                                       "old_start": 1,
                                       "old_lines": ["..."],
                                       "new_lines": ["..."]}],
                             "edited_full_file": "full file text"}))
                raw2 = await prov.complete(_SYSTEM_PROMPT + "\n" + nudge,
                                           user, temperature=0.0)
                obj = _parse_response(raw2)
            obj["fix_id"] = str(uuid.uuid4())
            obj["status"] = "ok"
            obj.pop("reason", None)
            return obj
        logger.info("no key set for %s; using deterministic fallback",
                    provider_name)
    except Exception as exc:
        logger.warning("AI provider failed (%s); using deterministic fallback",
                       exc)

    # --- deterministic fallback ----------------------------------------------
    local = _local_substitute(finding, file_contents)
    if local is not None:
        local["fix_id"] = str(uuid.uuid4())
        local["status"] = "ok"
        return local
    return _skipped(
        "no AI provider available and no deterministic patch registered for "
        f"rule {finding.get('pluginid','?')}. Configure an API key "
        "(/api/settings/keys) and retry."
    )
