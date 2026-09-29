import os
import time
import pytest
import subprocess
import sys
import psutil
from pathlib import Path
from neolock_core.supervisor import Supervisor
from neolock_core.capsule import TrustCapsule, Sensitivity

@pytest.fixture
def agent_proc():
    # Start a dummy agent that sleeps
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    yield proc
    try:
        proc.kill()
        proc.wait()
    except Exception:
        pass

@pytest.fixture
def capsule(tmp_path):
    return TrustCapsule(
        agent_id="test_agent",
        allowed_dirs=[str(tmp_path)],
        blocked_dirs=[],
        network_locked=False,
        max_files=100,
        max_sensitivity=Sensitivity.PUBLIC,
        ttl_expiry=0.0
    )

def test_canary_planting(agent_proc, capsule, tmp_path):
    sup = Supervisor(agent_pid=agent_proc.pid)
    sup.plant_canaries(capsule)
    
    canary_path = tmp_path / ".env.production.canary"
    assert canary_path.exists()
    assert canary_path.read_text() == "SECRET_KEY=mock_secret_key_12345"
    assert sup.is_canary(str(canary_path))
    
    sup.cleanup_canaries()
    assert not canary_path.exists()

def test_canary_modification_watchdog(agent_proc, capsule, tmp_path):
    sup = Supervisor(agent_pid=agent_proc.pid)
    sup.plant_canaries(capsule)
    
    canary_path = tmp_path / ".env.production.canary"
    assert canary_path.exists()
    
    # Modify canary
    with open(canary_path, "a") as f:
        f.write("\ntampered=1")
        
    # Wait for watchdog
    time.sleep(1)
    
    assert sup.quarantined
    assert sup.R_t == 1.0
    
    sup.cleanup_canaries()

def test_canary_mcp_read(agent_proc, capsule, tmp_path):
    sup = Supervisor(agent_pid=agent_proc.pid)
    sup.plant_canaries(capsule)
    
    canary_path = tmp_path / ".env.production.canary"
    
    req = {
        "params": {
            "name": "read_file",
            "arguments": {"path": str(canary_path)}
        }
    }
    sup.evaluate_mcp_event(req, "ALLOW", "")
    
    assert sup.quarantined
    assert sup.R_t == 1.0
    
    sup.cleanup_canaries()

def test_sequence_scoring_and_quarantine(agent_proc, capsule, tmp_path):
    sup = Supervisor(agent_pid=agent_proc.pid)
    sup.plant_canaries(capsule)
    
    # Send a few suspicious events
    req1 = {"params": {"name": "run_command", "arguments": {"cmd": "whoami"}}}
    req2 = {"params": {"name": "fetch", "arguments": {"url": "http://evil.com"}}}
    
    sup.evaluate_mcp_event(req1, "ALLOW", "")
    assert not sup.quarantined
    
    sup.evaluate_mcp_event(req2, "ALLOW", "")
    sup.evaluate_mcp_event(req2, "ALLOW", "")
    
    # It should drift upwards
    assert sup.R_t > 0.0
    # Add a high-risk block event (run_command out_of_capsule + sensitive_read)
    req_block = {"params": {"name": "run_command", "arguments": {"cmd": "cat /etc/shadow > backup.tar", "path": "/etc/shadow", "tar": "yes"}}}
    for _ in range(10):
        sup.evaluate_mcp_event(req_block, "BLOCK", "Path out of capsule")
        if sup.quarantined:
            break
            
    assert sup.quarantined
    assert sup.R_t >= 0.85
    
    sup.cleanup_canaries()

def test_process_suspend_resume_kill(agent_proc, capsule, tmp_path):
    sup = Supervisor(agent_pid=agent_proc.pid)
    sup.plant_canaries(capsule)
    
    p = psutil.Process(agent_proc.pid)
    # Give it a moment to actually start running
    time.sleep(0.5)
    
    sup.quarantine("Test manual quarantine")
    
    time.sleep(0.5)
    # Check if process is stopped
    # Note: On Windows STATUS_STOPPED may not be exactly reported the same, but let's check
    assert p.status() != psutil.STATUS_RUNNING
    
    # Resume
    sup.resume_agent_tree()
    time.sleep(0.5)
    
    # Kill
    sup.kill_agent_tree()
    time.sleep(0.5)
    assert not p.is_running()
    
    sup.cleanup_canaries()
