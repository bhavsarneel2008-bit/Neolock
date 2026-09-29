import asyncio
import json
import sys
import threading
from pathlib import Path
from neolock_core.logging import setup_logger

from neolock_core.capsule import TrustCapsule, evaluate_tool_call, Sensitivity, ACTIVE_CAPSULE
from neolock_core.ledger import append_to_ledger

logger = setup_logger("mcp_proxy")

async def hook_rules(req):
    decision, rule_id, reason = evaluate_tool_call(req, ACTIVE_CAPSULE)
    
    params = req.get("params", {})
    tool_name = params.get("name", "")
    tool_args = params.get("arguments", {})
    
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None, 
        append_to_ledger, 
        decision, 
        rule_id, 
        reason, 
        tool_name, 
        tool_args
    )
    
    return decision, f"[{rule_id}] {reason}" if reason else ""

async def hook_taint(req):
    return "ALLOW", ""

from neolock_core.rollback import stage_snapshot_for_request

async def hook_snapshot(req):
    req_id = req.get("id", "unknown")
    args = req.get("params", {}).get("arguments", {})
    
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        stage_snapshot_for_request,
        str(req_id),
        args
    )
    return "ALLOW", ""

from neolock_core.gatekeeper import hook_gatekeeper, ask_user_approval

async def evaluate_hooks(req):
    """
    Runs security hooks concurrently.
    Returns (decision, reason) where decision is ALLOW, BLOCK, or ASK.
    Priority: BLOCK > ASK > ALLOW.
    """
    results = await asyncio.gather(
        hook_rules(req),
        hook_taint(req),
        hook_gatekeeper(req),
        hook_snapshot(req)
    )
    
    ask_reason = None
    for decision, reason in results:
        if decision == "BLOCK":
            return "BLOCK", reason
        if decision == "ASK":
            ask_reason = reason
            
    if ask_reason:
        import os
        timeout = int(os.environ.get("NEOLOCK_ASK_TIMEOUT", "30"))
        approved = await ask_user_approval(req, ask_reason, timeout_sec=timeout)
        if not approved:
            return "BLOCK", f"User denied or timed out: {ask_reason}"
        
    return "ALLOW", ""

def _stdin_reader(loop, queue):
    """Synchronous thread to read stdin to avoid cross-platform asyncio pipe issues."""
    while True:
        try:
            line = sys.stdin.buffer.readline()
        except Exception:
            break
        if not line:
            loop.call_soon_threadsafe(queue.put_nowait, None)
            break
        loop.call_soon_threadsafe(queue.put_nowait, line)

class MCPProxy:
    def __init__(self, server_cmd):
        self.server_cmd = server_cmd
        self.process = None
        self.pending_requests = set()

    async def start(self):
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.server_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024 * 128 # 128MB limit for large messages
            )
        except Exception as e:
            logger.error(f"Failed to start server subprocess: {e}")
            sys.exit(1)

        await asyncio.gather(
            self.client_to_server(),
            self.server_to_client(),
            self.read_server_stderr()
        )

    async def read_server_stderr(self):
        while True:
            try:
                line = await self.process.stderr.readline()
            except ValueError:
                # Line too long, just read chunks in a real app, but for stderr it's rare
                continue
            except Exception:
                break
            if not line:
                break
            logger.debug(f"SERVER STDERR: {line.decode('utf-8', errors='replace').strip()}")

    async def server_to_client(self):
        while True:
            try:
                line = await self.process.stdout.readline()
            except Exception:
                break
            if not line:
                break
            
            # Pass through
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
            
            # Remove from pending requests
            try:
                resp = json.loads(line.decode('utf-8'))
                if isinstance(resp, list):
                    for item in resp:
                        if isinstance(item, dict) and "id" in item:
                            self.pending_requests.discard(item["id"])
                elif isinstance(resp, dict) and "id" in resp:
                    self.pending_requests.discard(resp["id"])
            except Exception:
                pass

        # If loop breaks, server has crashed or exited
        logger.error("Server stdout closed. Generating error for pending requests.")
        for req_id in list(self.pending_requests):
            err = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32000, "message": "Server crashed"}
            }
            sys.stdout.buffer.write((json.dumps(err) + "\n").encode('utf-8'))
        sys.stdout.buffer.flush()
        self.pending_requests.clear()

    async def handle_single_request(self, req, server_crashed):
        if not isinstance(req, dict):
            return None, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}

        req_id = req.get("id")
        method = req.get("method")
        
        if server_crashed:
            if req_id is not None:
                return None, {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": "Server crashed"}}
            return None, None

        if method is not None and not isinstance(method, str):
            if req_id is not None:
                return None, {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "Invalid Request"}}
            return None, None

        if "params" in req and not isinstance(req.get("params"), (dict, list)):
            if req_id is not None:
                return None, {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "Invalid Request"}}
            return None, None

        if method == "tools/call" and req_id is not None:
            decision, reason = await evaluate_hooks(req)
            if decision == "BLOCK":
                return None, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32000,
                        "message": f"Blocked by Neolock: {reason}"
                    }
                }
        
        if req_id is not None:
            self.pending_requests.add(req_id)
            
        return req, None

    async def process_batch(self, req_data, server_crashed):
        forward_batch = []
        response_batch = []
        coros = [self.handle_single_request(item, server_crashed) for item in req_data]
        results = await asyncio.gather(*coros)
        for fwd, rsp in results:
            if fwd is not None:
                forward_batch.append(fwd)
            if rsp is not None:
                response_batch.append(rsp)
                
        if response_batch:
            sys.stdout.buffer.write((json.dumps(response_batch) + "\n").encode('utf-8'))
            sys.stdout.buffer.flush()
        if forward_batch and not server_crashed:
            try:
                self.process.stdin.write((json.dumps(forward_batch) + "\n").encode('utf-8'))
                await self.process.stdin.drain()
            except Exception as e:
                logger.error(f"Write to server failed: {e}")

    async def process_single(self, req_data, server_crashed):
        fwd, rsp = await self.handle_single_request(req_data, server_crashed)
        if rsp is not None:
            sys.stdout.buffer.write((json.dumps(rsp) + "\n").encode('utf-8'))
            sys.stdout.buffer.flush()
        if fwd is not None and not server_crashed:
            try:
                self.process.stdin.write((json.dumps(fwd) + "\n").encode('utf-8'))
                await self.process.stdin.drain()
            except Exception as e:
                logger.error(f"Write to server failed: {e}")

    async def client_to_server(self):
        queue = asyncio.Queue()
        loop = asyncio.get_running_loop()
        threading.Thread(target=_stdin_reader, args=(loop, queue), daemon=True).start()

        while True:
            line = await queue.get()
            if line is None:
                logger.info("Client disconnected. Shutting down server.")
                if self.process:
                    try:
                        self.process.terminate()
                    except Exception:
                        pass
                break
            
            try:
                req_data = json.loads(line.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.error("Malformed JSON received from client.")
                sys.stdout.buffer.write((json.dumps({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"}
                }) + "\n").encode('utf-8'))
                sys.stdout.buffer.flush()
                continue

            server_crashed = (self.process is None or self.process.returncode is not None)
            
            if isinstance(req_data, list):
                if len(req_data) == 0:
                    resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
                    sys.stdout.buffer.write((json.dumps(resp) + "\n").encode('utf-8'))
                    sys.stdout.buffer.flush()
                    continue
                asyncio.create_task(self.process_batch(req_data, server_crashed))
            else:
                asyncio.create_task(self.process_single(req_data, server_crashed))

def run_proxy(server_cmd=None):
    if server_cmd is None:
        server_cmd = [sys.executable, "-m", "neolock_core.mock_server"]
    proxy = MCPProxy(server_cmd)
    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1:]
    else:
        cmd = [sys.executable, "-m", "neolock_core.mock_server"]
    run_proxy(cmd)
