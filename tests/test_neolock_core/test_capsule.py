import pytest
from pathlib import Path
from neolock_core.capsule import TrustCapsule, Sensitivity, evaluate_tool_call
import os

@pytest.fixture
def capsule():
    return TrustCapsule(
        agent_id="test_agent",
        allowed_dirs=[str(Path.cwd().resolve())],
        blocked_dirs=[],
        network_locked=True,
        max_files=1000,
        max_sensitivity=Sensitivity.PUBLIC,
        ttl_expiry=0.0,
        allow_shell=False
    )

def check_args(args: dict, capsule: TrustCapsule):
    req = {
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": args
        }
    }
    return evaluate_tool_call(req, capsule)

def test_safe_paths(capsule):
    decision, _, _ = check_args({"path": "file.txt"}, capsule)
    assert decision == "ALLOW"
    
    decision, _, _ = check_args({"path": "./file.txt"}, capsule)
    assert decision == "ALLOW"
    
    decision, _, _ = check_args({"path": "subfolder/file.txt"}, capsule)
    assert decision == "ALLOW"

def test_capsule_path_bypass_attempts(capsule):
    attempts = [
        # 1. Null byte
        {"path": "file.txt\x00"},
        # 2. URL encoded traversal
        {"path": "%2e%2e/etc/passwd"},
        # 3. URL encoded traversal alternative
        {"path": "..%2fetc%2fpasswd"},
        # 4. Traversal basic
        {"path": "../file.txt"},
        # 5. Traversal deep
        {"path": "../../../../../Windows/System32/cmd.exe"},
        # 6. Environment variables
        {"path": "%USERPROFILE%/Desktop/file.txt"},
        # 7. Home dir
        {"path": "~/Desktop/file.txt"},
        # 8. file URI
        {"path": "file:///C:/Windows/System32/cmd.exe"},
        # 9. Unicode lookalikes/NFKC
        {"path": "\uFF0E\uFF0E/Windows"}, # fullwidth dots
        # 10. Traversal with mixed slashes
        {"path": "..\\..\\..\\Windows/System32"},
        # 11. Network URL when network locked
        {"path": "http://evil.com/payload.sh"},
        # 12. HTTPS URL when network locked
        {"path": "https://evil.com"},
        # 13. FTP URL when network locked
        {"path": "ftp://evil.com"},
    ]
    
    # Windows specific checks
    if os.name == "nt":
        attempts.extend([
            # 14. UNC path
            {"path": "\\\\localhost\\c$\\Windows"},
            # 15. Device path
            {"path": "\\\\?\\C:\\Windows"},
            # 16. Local device path
            {"path": "\\\\.\\C:\\Windows"},
            # 17. Reserved device name NUL
            {"path": "NUL"},
            # 18. Reserved device name COM1
            {"path": "COM1.txt"},
            # 19. Reserved device name AUX
            {"path": "folder/aux"},
            # 20. Trailing dot
            {"path": "file.txt."},
            # 21. Trailing space
            {"path": "file.txt "},
            # 22. NTFS ADS standard
            {"path": "file.txt:stream"},
            # 23. NTFS ADS $DATA
            {"path": "file.txt::$DATA"},
            # 24. URL encoded ADS
            {"path": "file.txt%3Astream"},
            # 25. Deep ADS
            {"path": "folder/file.txt:hidden"},
            # 26. Absolute path outside allowed
            {"path": "C:\\Windows\\System32"},
            # 27. Forward slashes absolute path
            {"path": "C:/Windows/System32"},
            # 28. Mixed case check (if C:\\windows is blocked etc, but here outside allowed is blocked)
            {"path": "c:\\windows"},
            # 29. 8.3 short name bypass (PROGRA~1)
            {"path": "C:\\PROGRA~1"},
        ])
    else:
        # Pad with other cross-platform outside paths for the count
        attempts.extend([
            {"path": "/etc/passwd"},
            {"path": "/var/log/syslog"},
            {"path": "/usr/bin/bash"},
            {"path": "/bin/sh"},
            {"path": "//etc/passwd"},
            {"path": "/etc/../etc/passwd"},
            {"path": "file.txt%00.jpg"},
            {"path": "/tmp/test"},
            {"path": "ws://evil.com"},
            {"path": "wss://evil.com"},
            {"path": "/dev/null"},
            {"path": "/dev/random"},
            {"path": "....//....//etc/passwd"},
            {"path": "a/../../etc/passwd"},
            {"path": "/etc/passwd%00"},
            {"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
        ])
        
    for idx, arg in enumerate(attempts):
        decision, rule, reason = check_args(arg, capsule)
        assert decision in ["BLOCK", "ASK"], f"Test {idx+1} failed to block: {arg}. Decision: {decision}"

def test_shell_tool(capsule):
    req = {
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {"cmd": "echo hello"}
        }
    }
    decision, _, _ = evaluate_tool_call(req, capsule)
    assert decision == "ASK"

def test_network_tool(capsule):
    req = {
        "method": "tools/call",
        "params": {
            "name": "fetch",
            "arguments": {"url": "https://google.com"}
        }
    }
    decision, _, _ = evaluate_tool_call(req, capsule)
    assert decision == "BLOCK" # because network_locked = True

def test_unknown_tool(capsule):
    req = {
        "method": "tools/call",
        "params": {
            "name": "weird_tool",
            "arguments": {}
        }
    }
    decision, _, _ = evaluate_tool_call(req, capsule)
    assert decision == "ASK"

@pytest.mark.skipif(os.name != 'nt', reason="Windows-specific symlink/junction tests")
def test_junction_symlink_bypass(tmp_path):
    # This test verifies that symlinks/junctions pointing outside are resolved and blocked
    # Windows requires admin for symlinks, but mklink /J (junctions) usually doesn't,
    # however we'll just check if canonicalization correctly resolves existing symlinks.
    import subprocess
    
    capsule = TrustCapsule(
        agent_id="test_agent",
        allowed_dirs=[str(tmp_path)],
        blocked_dirs=[],
        network_locked=False,
        max_files=10,
        max_sensitivity=Sensitivity.PUBLIC,
        ttl_expiry=0.0
    )
    
    target_dir = tmp_path.parent / "outside_dir"
    target_dir.mkdir(exist_ok=True)
    (target_dir / "secret.txt").write_text("secret")
    
    link_path = tmp_path / "link_to_outside"
    
    # Try to create junction
    try:
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link_path), str(target_dir)], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        pytest.skip("Could not create junction (permissions).")

    # If junction created, scanning a file through it should be blocked because it resolves outside tmp_path
    req = {
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": str(link_path / "secret.txt")}
        }
    }
    decision, rule, reason = evaluate_tool_call(req, capsule)
    assert decision in ["BLOCK", "ASK"], f"Junction bypass succeeded: {decision} - {reason}"
