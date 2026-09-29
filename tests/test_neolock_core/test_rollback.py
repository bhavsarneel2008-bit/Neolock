import pytest
from pathlib import Path
from neolock_core.rollback import extract_paths_from_args, stage_snapshot_for_request, Snapshot, SNAPSHOT_DIR

def test_extract_paths(tmp_path):
    f1 = tmp_path / "test1.txt"
    f1.write_text("hello")
    f2 = tmp_path / "test2.json"
    f2.write_text("{}")
    
    # Path that doesn't exist shouldn't be staged
    f3 = tmp_path / "test3.txt"
    
    args = {
        "file_a": str(f1),
        "nested": {
            "file_b": str(f2)
        },
        "missing": str(f3),
        "just_text": "hello world"
    }
    
    paths = extract_paths_from_args(args)
    assert len(paths) == 2
    assert str(f1.absolute()) in paths
    assert str(f2.absolute()) in paths

def test_stage_and_rollback(tmp_path, monkeypatch):
    import neolock_core.rollback as rollback
    monkeypatch.setattr(rollback, "SNAPSHOT_DIR", tmp_path / ".snapshots")
    
    target = tmp_path / "target.txt"
    target.write_text("original content")
    
    # Stage snapshot
    snapshot = rollback.stage_snapshot_for_request("req123", {"file": str(target)})
    
    assert len(snapshot.files) == 1
    assert snapshot.files[0][0] == target.absolute()
    
    # Modify the original file
    target.write_text("modified content")
    assert target.read_text() == "modified content"
    
    # Rollback
    snapshot.rollback()
    
    # Verify rollback
    assert target.read_text() == "original content"
