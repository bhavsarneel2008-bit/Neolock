import json
import subprocess
import sys
import time

def send_request(proc, req_dict):
    proc.stdin.write(json.dumps(req_dict).encode('utf-8') + b'\n')
    proc.stdin.flush()

def read_response(proc):
    line = proc.stdout.readline()
    if not line:
        return None
    return json.loads(line.decode('utf-8'))

def test_mcp_proxy_e2e():
    import os
    env = os.environ.copy()
    env["NEOLOCK_ASK_TIMEOUT"] = "2"
    env["NEOLOCK_DISABLE_NLP_STAGE"] = "1"
    
    # Start proxy subprocess
    proc = subprocess.Popen(
        [sys.executable, "-m", "neolock_core.mcp_proxy"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )

    try:
        # Test 1: ALLOW (normal forwarding)
        req_allow = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "./pyproject.toml"}}
        }
        send_request(proc, req_allow)
        resp1 = read_response(proc)
        assert resp1 is not None
        assert resp1.get("id") == 1
        assert resp1.get("result", {}).get("status") == "success"

        # Test 2: BLOCK (triggered by path traversal outside allowed CWD)
        req_block = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "../../../Windows/System32/cmd.exe"}}
        }
        send_request(proc, req_block)
        resp2 = read_response(proc)
        assert resp2 is not None
        assert resp2.get("id") == 2
        assert "error" in resp2
        assert "Blocked by Neolock" in resp2["error"]["message"]

        # Test 3: ASK timeout (triggered by unknown tool)
        req_ask = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "trigger_ask"}
        }
        send_request(proc, req_ask)
        start_time = time.time()
        resp3 = read_response(proc)
        elapsed = time.time() - start_time
        assert resp3 is not None
        assert resp3.get("id") == 3
        assert "error" in resp3
        assert "User denied or timed out" in resp3["error"]["message"]
        assert elapsed >= 0.1

        # Test 4: Malformed JSON (must return -32700 Parse error)
        proc.stdin.write(b"not valid json\n")
        proc.stdin.flush()
        resp4 = read_response(proc)
        assert resp4 is not None
        assert resp4.get("error", {}).get("code") == -32700

        # Test 5: Verify proxy still alive after malformed input
        req_alive = {
            "jsonrpc": "2.0",
            "id": "string-id-5",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "./pyproject.toml"}}
        }
        send_request(proc, req_alive)
        resp5 = read_response(proc)
        assert resp5 is not None
        assert resp5.get("id") == "string-id-5"
        assert resp5.get("result", {}).get("status") == "success"
        
        # Test 6: Batch request with mixed allow and block
        req_batch = [
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "./pyproject.toml"}}},
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "../../../Windows/System32/cmd.exe"}}},
            {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "./pyproject.toml"}}}
        ]
        send_request(proc, req_batch)
        
        line1 = read_response(proc)
        line2 = read_response(proc)
        
        combined = []
        if isinstance(line1, list): combined.extend(line1)
        else: combined.append(line1)
        if isinstance(line2, list): combined.extend(line2)
        else: combined.append(line2)
        
        id_to_resp = {item.get("id"): item for item in combined if item}
        assert id_to_resp[6].get("result", {}).get("status") == "success"
        assert id_to_resp[7].get("error", {}).get("code") == -32000
        assert id_to_resp[8].get("result", {}).get("status") == "success"
        
        # Test 7: Invalid requests (bad method type)
        req_bad = {"jsonrpc": "2.0", "id": 9, "method": 123}
        send_request(proc, req_bad)
        resp_bad = read_response(proc)
        assert resp_bad.get("error", {}).get("code") == -32600
        
        # Test 8: Missing params type checks
        req_bad2 = {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": "string_params"}
        send_request(proc, req_bad2)
        resp_bad2 = read_response(proc)
        assert resp_bad2.get("error", {}).get("code") == -32600

        # Test 9: Concurrent ASK and ALLOW
        req_ask_concurrent = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "trigger_ask"}
        }
        req_allow_concurrent = {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "./pyproject.toml"}}
        }
        
        start_time = time.time()
        send_request(proc, req_ask_concurrent)
        time.sleep(0.05)
        send_request(proc, req_allow_concurrent)
        
        resp_fast = read_response(proc)
        fast_elapsed = time.time() - start_time
        assert resp_fast is not None
        assert resp_fast.get("id") == 12
        assert fast_elapsed < 1.0  # Should be faster than the 2s timeout
        
        resp_slow = read_response(proc)
        slow_elapsed = time.time() - start_time
        assert resp_slow is not None
        assert resp_slow.get("id") == 11
        assert "User denied or timed out" in resp_slow.get("error", {}).get("message", "")
        assert slow_elapsed >= 1.9  # 2s timeout

    finally:
        proc.terminate()
        proc.wait()
