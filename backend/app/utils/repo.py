import os
import shutil
import subprocess
import uuid
from pathlib import Path

def _prepare_tmp_dir() -> Path:
    tmp_root = Path('backend/tmp')
    tmp_root.mkdir(parents=True, exist_ok=True)
    uid = uuid.uuid4().hex
    work_dir = tmp_root / uid
    work_dir.mkdir()
    return work_dir

def clone_repo(repo_url: str) -> Path:
    """Clone a git repository into a temporary directory and return the path."""
    work_dir = _prepare_tmp_dir()
    subprocess.run(['git', 'clone', '--depth', '1', repo_url, str(work_dir)], check=True)
    return work_dir

def unpack_file(uploaded_file_path: str) -> Path:
    """Unpack a zip file (or tar.gz) into a temporary directory and return the path.
    `uploaded_file_path` should be an absolute path to the saved file.
    """
    work_dir = _prepare_tmp_dir()
    if uploaded_file_path.lower().endswith('.zip'):
        import zipfile
        with zipfile.ZipFile(uploaded_file_path, 'r') as zip_ref:
            zip_ref.extractall(work_dir)
    else:
        # fallback: just copy the file into the directory
        shutil.copy(uploaded_file_path, work_dir / Path(uploaded_file_path).name)
    return work_dir

def integrate_files(source_dir: str, target_repo_dir: str) -> None:
    """Copy files from `source_dir` into `target_repo_dir`, overwriting existing ones.
    This is a simple recursive copy.
    """
    src = Path(source_dir)
    dst = Path(target_repo_dir)
    for item in src.rglob('*'):
        if item.is_file():
            rel_path = item.relative_to(src)
            dest_path = dst / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, dest_path)
