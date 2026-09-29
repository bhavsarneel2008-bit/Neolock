import sqlite3
import json
import psutil
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from neolock_core.ledger import LEDGER_FILE, verify_ledger
from neolock_core.rollback import restore_all
from neolock_core.capsule import ACTIVE_CAPSULE
from neolock_core.supervisor import Supervisor
from pathlib import Path

app = FastAPI()

def get_ledger_records():
    if not LEDGER_FILE.exists():
        return []
    try:
        conn = sqlite3.connect(LEDGER_FILE)
        c = conn.cursor()
        c.execute("SELECT id, timestamp, tool_name, tool_args, decision, rule_id, reason, provenance, risk_score, latency_ms, execution_provider FROM ledger ORDER BY id DESC LIMIT 50")
        rows = c.fetchall()
        conn.close()
    except Exception:
        return []
    
    records = []
    for r in rows:
        try:
            args = json.loads(r[3])
        except:
            args = r[3]
            
        records.append({
            "id": r[0],
            "timestamp": r[1],
            "tool_name": r[2],
            "tool_args": args,
            "decision": r[4],
            "rule_id": r[5],
            "reason": r[6],
            "provenance": r[7],
            "risk_score": r[8],
            "latency_ms": r[9],
            "execution_provider": r[10]
        })
    return records

@app.get("/api/state")
def get_state():
    records = get_ledger_records()
    
    sup = Supervisor()
    for r in reversed(records):
        req = {"params": {"name": r["tool_name"], "arguments": r["tool_args"]}}
        sup.evaluate_mcp_event(req, r["decision"], r["reason"])
    
    is_valid, _ = verify_ledger()
    
    try:
        p = psutil.Process()
        children = p.children(recursive=True)
        net_conns = len(p.connections())
        for child in children:
            try:
                net_conns += len(child.connections())
            except:
                pass
    except Exception:
        net_conns = 0
        
    return {
        "capsule": {
            "agent_id": ACTIVE_CAPSULE.agent_id,
            "allowed_dirs": ACTIVE_CAPSULE.allowed_dirs,
            "network_locked": ACTIVE_CAPSULE.network_locked
        },
        "risk_score": round(sup.R_t, 3),
        "quarantined": sup.quarantined,
        "ledger_valid": is_valid,
        "privacy_connections": net_conns,
        "feed": records
    }

@app.post("/api/quarantine")
def trigger_quarantine():
    from neolock_core.ledger import append_to_ledger
    append_to_ledger("QUARANTINE", "USER", "Manual quarantine triggered from UI", "system", {}, "USER", 1.0, 0, "CPU")
    ACTIVE_CAPSULE.network_locked = True
    return {"status": "ok"}

@app.post("/api/rollback")
def trigger_rollback():
    restore_all(ACTIVE_CAPSULE.agent_id)
    return {"status": "ok"}

@app.get("/")
def index():
    html_path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(html_path.read_text())

def start_server():
    import uvicorn
    print("Starting Dashboard on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)

if __name__ == "__main__":
    start_server()
