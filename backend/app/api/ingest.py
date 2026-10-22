from fastapi import APIRouter, HTTPException, UploadFile, File, Body
from ..services.scan_manager import start_scan
from fastapi.responses import JSONResponse
from ..services.ingestion import clone_repo, unpack_upload
from pathlib import Path
import os

router = APIRouter()

@router.post('/repo')
async def ingest_repo(
    repo_url: str = Body(..., embed=True),
    branch: str | None = Body(None, embed=True),
    github_token: str | None = Body(None, embed=True),
    auth_confirmed: bool = Body(..., embed=True),
):
    """Clone a repository for scanning.
    Returns the absolute path of the prepared scan directory.
    """
    if not auth_confirmed:
        raise HTTPException(status_code=400, detail='Authorization not confirmed')
    try:
        scan_path: Path = clone_repo(repo_url, branch, github_token)
        scan_id = start_scan(scan_path)
        return JSONResponse(content={'scan_id': scan_id, 'scan_path': str(scan_path)})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.post('/upload')
async def ingest_upload(
    file: UploadFile = File(...),
    auth_confirmed: bool = Body(..., embed=True),
):
    """Accept a zip/tar upload and prepare a scan directory."""
    if not auth_confirmed:
        raise HTTPException(status_code=400, detail='Authorization not confirmed')
    # Save uploaded file to a temporary location
    temp_dir = Path('/tmp')
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f'{file.filename}'
    with open(temp_path, 'wb') as out_file:
        content = await file.read()
        out_file.write(content)
    try:
        scan_path: Path = unpack_upload(str(temp_path))
        # Clean up the uploaded archive
        os.remove(temp_path)
        scan_id = start_scan(scan_path)
        return JSONResponse(content={'scan_id': scan_id, 'scan_path': str(scan_path)})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
