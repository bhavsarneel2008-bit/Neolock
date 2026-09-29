import asyncio
import json
import traceback

def test_stage():
    try:
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "./pyproject.toml"}}}
        from neolock_core.mcp_proxy import evaluate_hooks
        decision, reason = asyncio.run(evaluate_hooks(req))
        print("DECISION:", decision)
        print("REASON:", reason)
    except Exception as e:
        print("CRASH!")
        traceback.print_exc()

test_stage()
