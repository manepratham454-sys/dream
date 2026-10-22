import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Tuple

# Base directory for temporary scan workspaces
SCAN_ROOT = os.getenv('SCAN_ROOT', str(Path(tempfile.gettempdir()) / 'sentinel_scans'))

def _ensure_scan_root() -> Path:
    root = Path(SCAN_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    return root

def _prepare_scan_dir() -> Path:
    root = _ensure_scan_root()
    uid = uuid.uuid4().hex
    work_dir = root / uid
    work_dir.mkdir(parents=True)
    return work_dir

def clone_repo(repo_url: str, branch: str | None = None, token: str | None = None) -> Path:
    """Clone a GitHub repository into an isolated temporary directory.
    - Uses a shallow clone (`--depth 1`).
    - If a personal access token is provided, it is injected into the URL using
      the ``https://{token}@github.com/...`` pattern (GitHub accepts token as username).
    - Optional ``branch`` overrides the default branch.
    Returns the path to the cloned repository.
    """
    work_dir = _prepare_scan_dir()
    auth_url = repo_url
    if token:
        # Insert token after protocol, e.g. https://<token>@github.com/owner/repo.git
        if repo_url.startswith('https://'):
            auth_url = repo_url.replace('https://', f'https://{token}@')
        elif repo_url.startswith('http://'):
            auth_url = repo_url.replace('http://', f'http://{token}@')
    clone_cmd = ['git', 'clone', '--depth', '1']
    if branch:
        clone_cmd.extend(['--branch', branch])
    clone_cmd.extend([auth_url, str(work_dir)])
    subprocess.run(clone_cmd, check=True)
    return work_dir

def unpack_upload(upload_path: str) -> Path:
    """Extract a zip/tar archive into a temporary directory.
    Returns the path to the extracted directory.
    """
    work_dir = _prepare_scan_dir()
    lower = upload_path.lower()
    if lower.endswith('.zip'):
        import zipfile
        with zipfile.ZipFile(upload_path, 'r') as zf:
            zf.extractall(work_dir)
    elif lower.endswith(('.tar', '.tar.gz', '.tgz', '.gz')):
        import tarfile
        with tarfile.open(upload_path, 'r:*') as tf:
            tf.extractall(work_dir)
    else:
        # Fallback: copy the file as‑is
        shutil.copy2(upload_path, work_dir / Path(upload_path).name)
    return work_dir
