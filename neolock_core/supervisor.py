import os
import math
import psutil
import threading
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from neolock_core.logging import setup_logger
from neolock_core.capsule import TrustCapsule
from neolock_core.ledger import append_to_ledger
from typing import Dict, Any, List

logger = setup_logger("supervisor")

WEIGHTS = {
    "sensitive_read": 1.5,
    "archive_creation": 1.0,
    "subprocess_spawn": 2.0,
    "network_open": 2.0,
    "out_of_capsule": 3.0
}
BIAS = -2.0
LAMBDA = 0.7
THRESHOLD = 0.85

def sigmoid(x: float) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0

class CanaryHandler(FileSystemEventHandler):
    def __init__(self, supervisor):
        self.supervisor = supervisor

    def on_modified(self, event):
        if not event.is_directory and self.supervisor.is_canary(event.src_path):
            self.supervisor.trigger_canary(f"Canary modification detected: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory and self.supervisor.is_canary(event.src_path):
            self.supervisor.trigger_canary(f"Canary deletion detected: {event.src_path}")

    def on_moved(self, event):
        if not event.is_directory and (self.supervisor.is_canary(event.src_path) or self.supervisor.is_canary(event.dest_path)):
            self.supervisor.trigger_canary(f"Canary move detected: {event.src_path} -> {event.dest_path}")

class Supervisor:
    def __init__(self, agent_pid: int = None):
        self.agent_pid = agent_pid
        self.R_t = 0.0
        self.canaries = set()
        self.active_capsule = None
        self.observer = None
        self.quarantined = False
        self.lock = threading.Lock()
        self.airlock_pids = set()

    def plant_canaries(self, capsule: TrustCapsule):
        self.active_capsule = capsule
        self._update_airlock_pids()
        
        for d in capsule.allowed_dirs:
            d_path = Path(d)
            if not d_path.exists():
                continue
            canary = d_path / ".env.production.canary"
            try:
                if canary.exists():
                    if os.name == 'nt':
                        import ctypes
                        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
                        kernel32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
                        kernel32.SetFileAttributesW.restype = ctypes.c_int
                        kernel32.SetFileAttributesW(str(canary.resolve()), 0x80)
                    canary.unlink()
                    
                canary.write_text("SECRET_KEY=mock_secret_key_12345")
                self.canaries.add(str(canary.resolve()))
                
                if os.name == 'nt':
                    import ctypes
                    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
                    kernel32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
                    kernel32.SetFileAttributesW.restype = ctypes.c_int
                    kernel32.SetFileAttributesW(str(canary.resolve()), 0x02) # FILE_ATTRIBUTE_HIDDEN
            except Exception as e:
                logger.warning(f"Could not plant canary in {d}: {e}")
                
        self.observer = Observer()
        handler = CanaryHandler(self)
        for d in capsule.allowed_dirs:
            if Path(d).exists():
                self.observer.schedule(handler, d, recursive=True)
        self.observer.start()
        logger.info(f"Supervisor started. Canaries planted: {self.canaries}")

    def cleanup_canaries(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
        for c in self.canaries:
            try:
                if os.name == 'nt':
                    import ctypes
                    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
                    kernel32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
                    kernel32.SetFileAttributesW.restype = ctypes.c_int
                    kernel32.SetFileAttributesW(c, 0x80)
                os.remove(c)
            except Exception:
                pass
        self.canaries.clear()

    def _update_airlock_pids(self):
        try:
            p = psutil.Process()
            self.airlock_pids.add(p.pid)
            while p.parent():
                p = p.parent()
                self.airlock_pids.add(p.pid)
        except Exception:
            pass

    def is_canary(self, path: str) -> bool:
        if not path:
            return False
        try:
            p = str(Path(path).resolve())
            return p in self.canaries
        except Exception:
            return False

    def trigger_canary(self, reason: str):
        with self.lock:
            self._update_score({"canary_t": 1.0}, f"Canary tripped: {reason}")

    def evaluate_mcp_event(self, req: dict, decision: str, reason: str):
        params = req.get("params", {})
        tool_name = params.get("name", "")
        args = params.get("arguments", {})
        
        f = {
            "sensitive_read": 0,
            "archive_creation": 0,
            "subprocess_spawn": 0,
            "network_open": 0,
            "out_of_capsule": 0,
            "canary_t": 0.0
        }
        
        if tool_name in ["read_file", "view_file", "run_command", "bash"]:
            path = str(args.get("path", "")) + str(args.get("cmd", ""))
            if self.is_canary(path) or self.is_canary(args.get("path", "")):
                f["canary_t"] = 1.0
            if any(s in path for s in [".env", "id_rsa", "passwd", "shadow", "config.json"]):
                f["sensitive_read"] = 1
                
        if tool_name in ["write_file", "create_file", "run_command", "bash"]:
            if "tar" in str(args) or "zip" in str(args):
                f["archive_creation"] = 1
                
        if tool_name in ["run_command", "bash", "python", "cmd", "run_script"]:
            f["subprocess_spawn"] = 1
            
        if tool_name in ["fetch", "curl", "wget", "request", "browser"]:
            f["network_open"] = 1
            
        if decision == "BLOCK" and ("path" in str(reason).lower() or "blocked directory" in str(reason).lower()):
            f["out_of_capsule"] = 1
            
        with self.lock:
            self._update_score(f, f"MCP event: {tool_name}")

    def _update_score(self, features: dict, context: str):
        if self.quarantined:
            return
            
        canary_t = features.pop("canary_t", 0.0)
        
        w_dot_f = sum(features.get(k, 0) * WEIGHTS.get(k, 0) for k in WEIGHTS)
        r_t = sigmoid(w_dot_f + BIAS)
        
        self.R_t = max(canary_t, LAMBDA * self.R_t + (1 - LAMBDA) * r_t)
        
        logger.debug(f"[{context}] Features: {features} | r_t: {r_t:.3f} | R_t: {self.R_t:.3f}")
        
        if self.R_t >= THRESHOLD:
            self.quarantine(context)

    def quarantine(self, reason: str):
        self.quarantined = True
        logger.warning(f"QUARANTINE TRIGGERED! Score: {self.R_t:.3f} >= {THRESHOLD}. Reason: {reason}")
        
        self.suspend_agent_tree()
        
        if self.active_capsule:
            self.active_capsule.network_locked = True
            
        append_to_ledger(
            decision="QUARANTINE",
            rule_id="SUPERVISOR",
            reason=f"Behavior drift score reached {self.R_t:.3f}: {reason}",
            tool_name="supervisor_daemon",
            tool_args={},
            provenance="SYSTEM"
        )

    def suspend_agent_tree(self):
        if not self.agent_pid:
            return
        try:
            parent = psutil.Process(self.agent_pid)
            children = parent.children(recursive=True)
            for child in children:
                if child.pid not in self.airlock_pids:
                    try:
                        child.suspend()
                    except psutil.NoSuchProcess:
                        pass
            if parent.pid not in self.airlock_pids:
                try:
                    parent.suspend()
                except psutil.NoSuchProcess:
                    pass
        except psutil.NoSuchProcess:
            pass

    def resume_agent_tree(self):
        if not self.agent_pid:
            return
        try:
            parent = psutil.Process(self.agent_pid)
            children = parent.children(recursive=True)
            for child in children:
                if child.pid not in self.airlock_pids:
                    try:
                        child.resume()
                    except psutil.NoSuchProcess:
                        pass
            if parent.pid not in self.airlock_pids:
                try:
                    parent.resume()
                except psutil.NoSuchProcess:
                    pass
        except psutil.NoSuchProcess:
            pass

    def kill_agent_tree(self):
        if not self.agent_pid:
            return
        try:
            parent = psutil.Process(self.agent_pid)
            children = parent.children(recursive=True)
            for child in children:
                if child.pid not in self.airlock_pids:
                    try:
                        child.kill()
                    except psutil.NoSuchProcess:
                        pass
            if parent.pid not in self.airlock_pids:
                try:
                    parent.kill()
                except psutil.NoSuchProcess:
                    pass
        except psutil.NoSuchProcess:
            pass
