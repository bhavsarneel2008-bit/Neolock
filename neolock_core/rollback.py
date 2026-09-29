import os
import shutil
import uuid
import re
from pathlib import Path
from typing import List, Any, Tuple
from neolock_core.logging import setup_logger

logger = setup_logger("rollback")

SNAPSHOT_DIR = Path(".neolock/snapshots")

def extract_paths_from_args(args: Any) -> List[str]:
    paths = []
    if isinstance(args, str):
        # Quick heuristic for potential paths that exist
        if len(args) < 1024 and ("\\" in args or "/" in args or re.search(r'\.[a-zA-Z0-9]{1,5}$', args)):
            try:
                p = Path(args)
                if p.exists() and p.is_file():
                    paths.append(str(p.absolute()))
            except Exception:
                pass
    elif isinstance(args, list):
        for item in args:
            paths.extend(extract_paths_from_args(item))
    elif isinstance(args, dict):
        for v in args.values():
            paths.extend(extract_paths_from_args(v))
    return paths

class Snapshot:
    def __init__(self, req_id: str):
        self.req_id = str(req_id)
        self.backup_dir = SNAPSHOT_DIR / self.req_id
        self.files: List[Tuple[Path, Path]] = []
        
    def stage_file(self, filepath: str):
        target = Path(filepath).absolute()
        if not target.exists() or not target.is_file():
            return
            
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = self.backup_dir / target.name
        
        # Handle filename collisions in the same snapshot
        counter = 1
        while backup_path.exists():
            backup_path = self.backup_dir / f"{target.stem}_{counter}{target.suffix}"
            counter += 1
            
        try:
            shutil.copy2(target, backup_path)
            self.files.append((target, backup_path))
            logger.debug(f"Staged snapshot for {target}")
        except Exception as e:
            logger.error(f"Failed to stage snapshot for {target}: {e}")
            
    def rollback(self):
        for original, backup in self.files:
            try:
                shutil.copy2(backup, original)
                logger.info(f"Rolled back {original}")
            except Exception as e:
                logger.error(f"Failed to rollback {original}: {e}")

def stage_snapshot_for_request(req_id: str, args: Any) -> Snapshot:
    snapshot = Snapshot(req_id)
    paths = extract_paths_from_args(args)
    for p in set(paths):
        snapshot.stage_file(p)
    return snapshot

def restore_all(capsule_id: str = None):
    # Dummy implementation for dashboard
    if not SNAPSHOT_DIR.exists():
        return
    for req_dir in SNAPSHOT_DIR.iterdir():
        if req_dir.is_dir():
            # In a full implementation, we'd read metadata about which file goes where.
            # Here we just log.
            logger.info(f"Restoring all from {req_dir.name}")
