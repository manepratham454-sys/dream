"""Scan endpoints for the Sentinel outpost."""
import logging
import shutil
import tempfile
import zipfile
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Form, HTTPException, UploadFile
from pydantic import BaseModel

from ..services.sast import run_scan as run_sast_scan
from ..services.zap import run_scan

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scan"])

# In-memory storage for scan results (keyed by scan_id).
scans: dict[str, dict] = {}

# Recognised archive extensions for SAST uploads.
_ARCHIVE_SUFFIXES = {".zip", ".tar", ".tar.gz", ".tgz", ".gz"}


class ScanResponse(BaseModel):
    scan_id: str
    message: str
    target_url: str
    status: str
    alert_count: int
    source: str | None = None


def _safe_suffix(name: str | None) -> str:
    """Return a lowercase suffix we recognise, or '.bin' for unknown names."""
    if not name:
        return ".bin"
    lower = name.lower()
    for suf in (".tar.gz", ".tar", ".tgz", ".gz", ".zip"):
        if lower.endswith(suf):
            return suf
    return Path(lower).suffix or ".bin"


def _extract_archive(archive_path: Path, dest: Path) -> bool:
    """Extract ``archive_path`` into ``dest``. Returns True on success.

    Handles ``.zip`` and ``.tar``/``.tar.gz`` natively. Refuses path-
    absolute or `..` entries (zip-slip / tar-slip protection).
    """
    import tarfile

    suffix = "".join(archive_path.suffixes).lower()
    try:
        if suffix == ".zip":
            with zipfile.ZipFile(archive_path) as zf:
                for member in zf.namelist():
                    if member.startswith(("/", "\\")) or ".." in Path(member).parts:
                        raise ValueError(f"Unsafe zip entry: {member}")
                zf.extractall(dest)
        elif suffix in {".tar", ".tar.gz", ".tgz", ".gz"}:
            with tarfile.open(archive_path) as tf:
                base = dest.resolve()
                for member in tf.getmembers():
                    target = (dest / member.name).resolve()
                    try:
                        target.relative_to(base)
                    except ValueError:
                        raise ValueError(f"Unsafe tar entry: {member.name}")
                tf.extractall(dest)
        else:
            # Treat as a single source file: copy it into dest/.
            shutil.copy2(archive_path, dest / archive_path.name)
        return True
    except Exception:
        logger.exception("archive extraction failed for %s", archive_path)
        return False


async def _sast_scan_from_upload(file: UploadFile) -> dict:
    """Save an uploaded archive, extract it, run SAST, return scan result."""
    tmp_archive = Path(tempfile.mkstemp(suffix=_safe_suffix(file.filename))[1])
    try:
        # Drain the UploadFile inside a single `with` so the underlying
        # SpooledTemporaryFile handle is closed here — Windows refuses to
        # delete a still-open file (WinError 32).
        try:
            with tmp_archive.open("wb") as fh:
                shutil.copyfileobj(file.file, fh)
        finally:
            await file.close()

        work_dir = Path(tempfile.mkdtemp(prefix="sentinel-sast-"))
        try:
            if not _extract_archive(tmp_archive, work_dir):
                # Fall back: treat the single uploaded file as the whole tree.
                shutil.copy2(tmp_archive, work_dir / (file.filename or "upload"))
            # Some archives unzip into a single nested dir — flatten if so.
            children = list(work_dir.iterdir())
            scan_root = (
                children[0]
                if len(children) == 1 and children[0].is_dir()
                else work_dir
            )
            return await run_sast_scan(file.filename or "upload", scan_root)
        finally:
            # Best-effort cleanup; never let a temp-file cleanup failure
            # surface to the API caller (Windows can briefly hold handles).
            shutil.rmtree(work_dir, ignore_errors=True)
    finally:
        try:
            tmp_archive.unlink(missing_ok=True)
        except (PermissionError, OSError):
            # OS will reap the temp dir on shutdown; not worth a 500.
            logger.debug("could not delete temp archive %s", tmp_archive)



@router.post("/scans", response_model=ScanResponse)
async def start_scan(
    url: str | None = Form(None),
    file: UploadFile | None = None,
):
    """Start a security scan for the given target.

    * URL given  -> live (or mock) ZAP-style scan of the running service.
    * File given -> static SAST (heuristic + secrets + optional bandit /
                   semgrep) of the uploaded source archive.
    At least one of the two is required.
    """
    if not url and not file:
        raise HTTPException(status_code=400, detail="Provide a `url` or `file`.")

    if file is not None:
        result = await _sast_scan_from_upload(file)
        target_url = file.filename or "uploaded-archive"
    else:
        target_url = url
        result = await run_scan(target_url)

    scan_id = str(uuid4())
    scans[scan_id] = {
        "scan_id": scan_id,
        "target_url": target_url,
        "status": result.get("status", "completed"),
        "alerts": result.get("alerts", []),
        "source": result.get("source"),
    }

    return ScanResponse(
        scan_id=scan_id,
        message="Scan completed",
        target_url=target_url,
        status=result.get("status", "completed"),
        alert_count=len(result.get("alerts", [])),
        source=result.get("source"),
    )


@router.get("/scans")
async def list_scans():
    """Return metadata for every scan performed in this process."""
    return [
        {
            "scan_id": sid,
            "target_url": s.get("target_url"),
            "status": s.get("status"),
            "source": s.get("source"),
            "alert_count": len(s.get("alerts", [])),
        }
        for sid, s in scans.items()
    ]
