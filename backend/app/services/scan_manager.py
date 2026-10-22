import asyncio
import uuid
from pathlib import Path
from typing import Dict, Any
import logging

from .static_analysis import run_static_analysis

logger = logging.getLogger(__name__)

# Global in‑memory store for scans
_scans: Dict[str, Dict[str, Any]] = {}

def get_scan(scan_id: str) -> Dict[str, Any] | None:
    return _scans.get(scan_id)

def start_scan(scan_path: Path) -> str:
    """Create a scan entry and launch the static‑analysis pipeline in the background.
    Returns the generated scan_id.
    """
    scan_id = uuid.uuid4().hex
    _scans[scan_id] = {
        "status": "pending",
        "result": None,
        "error": None,
    }
    # Run the heavy work in a thread pool to avoid blocking the event loop
    async def _run():
        try:
            _scans[scan_id]["status"] = "running"
            logger.info("Starting static analysis for scan %s", scan_id)
            result = await asyncio.get_event_loop().run_in_executor(None, run_static_analysis, scan_path)
            _scans[scan_id]["status"] = "completed"
            _scans[scan_id]["result"] = result
        except Exception as exc:
            logger.exception("Static analysis failed for scan %s", scan_id)
            _scans[scan_id]["status"] = "failed"
            _scans[scan_id]["error"] = str(exc)
    asyncio.create_task(_run())
    return scan_id
