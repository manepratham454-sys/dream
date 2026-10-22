"""Apply generated fixes to disk — with strict safety rails.

Two-phase by design:
  1. ``preview_batch`` — resolve every fix to an exact file-change record
     WITHOUT writing. This is the "Confirm" screen data.
  2. ``apply_batch(fixes, project_root, confirmed=True)`` — write
     atomically. Before any write we snapshot: a ``git commit`` if the
     project is a repo, else a ``.sentinel-bak-<ts>`` sibling per file.
     If any write fails, prior writes in the batch are rolled back from
     their captured pre-image so we never leave a half-edited tree.

Public API:
    preview_batch(fixes, project_root) -> list[dict]
    apply_batch(fixes, project_root, *, confirmed=False) -> list[dict]
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Files apply.py will NEVER touch, regardless of what the model proposes.
_FORBIDDEN_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".bin", ".pyc",
                       ".lock", ".env"}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _resolve_safe(project_root: Path, rel_path: str) -> Path:
    """Resolve ``rel_path`` under ``project_root``; reject escapes.

    Returns the absolute path inside project_root, or raises ValueError if
    the resolved path would land outside the root (../ escape, absolute
    paths, drive-relative on Windows) or matches a forbidden suffix.
    """
    root = project_root.resolve()
    cleaned = rel_path.lstrip("/\\")
    candidate = (root / cleaned).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"refusing to write outside project root: {rel_path!r}"
        ) from exc
    if candidate.suffix.lower() in _FORBIDDEN_SUFFIXES:
        raise ValueError(f"refusing to modify {candidate.suffix} file: {rel_path}")
    return candidate


def _backup_via_git(project_root: Path) -> bool:
    """Create a git commit snapshotting current tracked state.

    We use ``git add -A`` because the user explicitly opted into the
    pre-apply backup; untracked files are staged too so the snapshot is
    complete and ``git reset --hard HEAD~1`` fully reverses the apply.
    Returns True on success, False (-> caller falls back to .bak) on error.
    """
    if not (project_root / ".git").is_dir():
        return False
    try:
        subprocess.run(["git", "add", "-A"], cwd=str(project_root),
                       capture_output=True, timeout=30)
        subprocess.run(
            ["git", "commit", "-m",
             f"sentinel: pre-apply backup @ {time.strftime('%Y-%m-%dT%H:%M:%S')}"],
            cwd=str(project_root), capture_output=True, timeout=30,
        )
        return True
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("git backup failed (%s); will fall back to .bak", exc)
        return False


def _backup_via_files(project_root: Path, targets: list[Path]) -> bool:
    """Copy each existing target to a ``.sentinel-bak-<ts>`` sibling.

    Used when the project isn't a git repo. Missing target files (new-file
    creates) are skipped since there's nothing to back up.
    """
    ts = time.strftime("%Y%m%dT%H%M%S")
    wrote = 0
    for t in targets:
        if not t.is_file():
            continue
        bak = t.with_name(f"{t.name}.sentinel-bak-{ts}")
        try:
            shutil.copy2(t, bak)
            wrote += 1
        except OSError as exc:
            logger.warning("backup copy failed for %s (%s)", t, exc)
    return wrote > 0 or not targets


def _action_for(target: Path) -> str:
    return "modify" if target.is_file() else "create"


def preview_batch(fixes: list[dict], project_root: str | Path) -> list[dict]:
    """Resolve every fix to an exact file-change record WITHOUT writing.

    Each ``fix`` must have ``file`` (relative path) and ``edited_full_file``
    (the proposed full new content). Returns one record per fix:
      {file, action, sha_before, sha_after, bytes_changed, status}

    This is the data the Confirm screen renders before the user approves.
    """
    root = Path(project_root).resolve()
    out: list[dict] = []
    for fix in fixes:
        rel = fix.get("file", "")
        new_text = fix.get("edited_full_file", "")
        rec: dict = {"file": rel, "status": "ok", "error": None}
        try:
            target = _resolve_safe(root, rel)
            old = target.read_text("utf-8") if target.is_file() else ""
            old_b = old.encode("utf-8")
            new_b = new_text.encode("utf-8")
            rec["action"] = _action_for(target)
            rec["sha_before"] = _sha(old)
            rec["sha_after"] = _sha(new_text)
            rec["bytes_changed"] = abs(len(new_b) - len(old_b)) + (
                sum(1 for a, b in zip(old_b, new_b) if a != b) * 2
            )
        except ValueError as exc:
            rec.update(action="skip", sha_before=None, sha_after=None,
                       bytes_changed=0, status="rejected", error=str(exc))
        except OSError as exc:
            rec.update(action="skip", sha_before=None, sha_after=None,
                       bytes_changed=0, status="error", error=str(exc))
        out.append(rec)
    return out


def apply_batch(fixes: list[dict], project_root: str | Path, *,
                confirmed: bool = False) -> list[dict]:
    """Write every fix to disk atomically, after a safety backup.

    Refuses unless ``confirmed=True`` (defence-in-depth for the
    "never auto-apply without confirmation" rule).

    Sequence:
      1. Resolve + pre-snapshot every target's current bytes (for rollback).
      2. Backup: git commit if a repo, else ``.sentinel-bak-<ts>`` copies.
      3. Atomic write per file (write temp -> os.replace). On ANY failure,
         roll back every file already written from its pre-image.
    """
    if not confirmed:
        raise ValueError(
            "apply_batch refused: pass confirmed=True. Sentinel never writes "
            "without explicit confirmation (preview_batch first)."
        )

    root = Path(project_root).resolve()
    records: list[dict] = []
    pre_images: list[tuple[Path, bytes, bool]] = []  # (path, old, existed)
    written: list[tuple[int, Path, bytes, bool]] = []  # (idx, path, old, ex)

    # 1. Resolve + snapshot every target.
    for fix in fixes:
        rel = fix.get("file", "")
        new_text = fix.get("edited_full_file", "")
        rec: dict = {"file": rel, "applied": False, "error": None}
        try:
            target = _resolve_safe(root, rel)
            if target.is_file():
                old_bytes = target.read_bytes()
                pre_images.append((target, old_bytes, True))
            else:
                pre_images.append((target, b"", False))
            rec["action"] = "modify" if target.is_file() else "create"
            rec["sha_before"] = _sha(
                pre_images[-1][1].decode("utf-8", "ignore"))
            rec["sha_after"] = _sha(new_text)
        except ValueError as exc:
            pre_images.append((None, b"", False))
            rec.update(action="skip", sha_before=None, sha_after=None,
                       error=str(exc))
        records.append(rec)

    # 2. Safety backup (best-effort; never blocks the apply).
    existing = [p for (p, _b, ex) in pre_images if p and ex]
    if (root / ".git").is_dir():
        _backup_via_git(root)
    elif existing:
        _backup_via_files(root, existing)

    # 3. Atomic writes; full rollback on the first failure.
    for idx, fix in enumerate(fixes):
        target, _old, _existed = pre_images[idx]
        rec = records[idx]
        if target is None:
            continue  # already rejected in step 1
        new_bytes = fix.get("edited_full_file", "").encode("utf-8")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(f".{target.name}.sentinel-tmp")
            tmp.write_bytes(new_bytes)
            os.replace(tmp, target)  # atomic on the same filesystem
            written.append((idx, target, _old, _existed))
            rec["applied"] = True
        except OSError as exc:
            logger.error("write failed for %s: %s — rolling back batch",
                         target, exc)
            rec["error"] = f"write failed: {exc}"
            rec["applied"] = False
            # Roll back everything already written this run.
            for ridx, rpath, rold, rex in reversed(written):
                try:
                    if rex:
                        rpath.write_bytes(rold)
                    else:
                        rpath.unlink(missing_ok=True)
                    records[ridx]["applied"] = False
                    records[ridx]["error"] = (records[ridx]["error"] or
                                              "rolled back after batch failure")
                    records[ridx]["rolled_back"] = True
                except OSError as rb:
                    records[ridx]["error"] = (
                        f"rollback FAILED: {rb} — file may be inconsistent; "
                        "restore manually from the backup."
                    )
            break
    return records


