import json
import struct
import hashlib
from typing import List, Tuple, Dict, Any
from pathlib import Path
from pydantic import BaseModel
from datetime import datetime, timezone
from neolock_core.platform_utils import protect_data, unprotect_data

LEDGER_FILE = Path(".neolock/ledger.enc")

class LedgerEntry(BaseModel):
    timestamp: float
    decision: str
    rule_id: str
    reason: str
    tool_name: str
    tool_args: Dict[str, Any]
    provenance: str = "USER"
    risk_score: float = 0.0
    latency: float = 0.0
    execution_provider: str = "CPU"
    prev_hash: str
    entry_hash: str = ""

def calculate_hash(entry: LedgerEntry) -> str:
    # Hash everything except the entry_hash itself
    data = f"{entry.timestamp}|{entry.decision}|{entry.rule_id}|{entry.reason}|{entry.tool_name}|{json.dumps(entry.tool_args, sort_keys=True)}|{entry.provenance}|{entry.risk_score}|{entry.latency}|{entry.execution_provider}|{entry.prev_hash}"
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def get_last_hash() -> str:
    if not LEDGER_FILE.exists():
        return "0" * 64
        
    prev_hash = "0" * 64
    with open(LEDGER_FILE, "rb") as f:
        while True:
            len_bytes = f.read(4)
            if not len_bytes:
                break
            if len(len_bytes) != 4:
                break
            length = struct.unpack("<I", len_bytes)[0]
            blob = f.read(length)
            if len(blob) != length:
                break
            try:
                json_data = unprotect_data(blob)
                entry_dict = json.loads(json_data.decode('utf-8'))
                prev_hash = entry_dict.get("entry_hash", prev_hash)
            except Exception:
                break
    return prev_hash

def append_to_ledger(decision: str, rule_id: str, reason: str, tool_name: str, tool_args: dict, provenance: str = "USER", risk_score: float = 0.0, latency: float = 0.0, execution_provider: str = "CPU"):
    LEDGER_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    prev_hash = get_last_hash()
    
    entry = LedgerEntry(
        timestamp=datetime.now(timezone.utc).timestamp(),
        decision=decision,
        rule_id=rule_id,
        reason=reason,
        tool_name=tool_name,
        tool_args=tool_args,
        provenance=provenance,
        risk_score=risk_score,
        latency=latency,
        execution_provider=execution_provider,
        prev_hash=prev_hash
    )
    entry.entry_hash = calculate_hash(entry)
    
    json_data = entry.model_dump_json().encode('utf-8')
    protected = protect_data(json_data)
    
    with open(LEDGER_FILE, "ab") as f:
        f.write(struct.pack("<I", len(protected)))
        f.write(protected)

def verify_ledger() -> Tuple[bool, str]:
    if not LEDGER_FILE.exists():
        return True, "Ledger is empty"
        
    prev_hash = "0" * 64
    idx = 0
    with open(LEDGER_FILE, "rb") as f:
        while True:
            len_bytes = f.read(4)
            if not len_bytes:
                break
            if len(len_bytes) != 4:
                return False, f"Tamper detected at index {idx}: incomplete length header"
                
            length = struct.unpack("<I", len_bytes)[0]
            blob = f.read(length)
            if len(blob) != length:
                return False, f"Tamper detected at index {idx}: incomplete data blob"
                
            try:
                json_data = unprotect_data(blob)
                entry_dict = json.loads(json_data.decode('utf-8'))
                entry = LedgerEntry(**entry_dict)
            except Exception as e:
                return False, f"Tamper detected at index {idx}: decryption or parse failed ({e})"
                
            if entry.prev_hash != prev_hash:
                return False, f"Tamper detected at index {idx}: prev_hash mismatch"
                
            expected_hash = calculate_hash(entry)
            if entry.entry_hash != expected_hash:
                return False, f"Tamper detected at index {idx}: entry_hash mismatch"
                
            prev_hash = entry.entry_hash
            idx += 1
            
    return True, f"Ledger verified successfully ({idx} entries)"
