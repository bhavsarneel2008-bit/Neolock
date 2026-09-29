import asyncio
from pathlib import Path
from attack_lab.replay_engine import ReplayEngine
from neolock_core.gatekeeper import deterministic_stage_1

async def run():
    engine = ReplayEngine(Path("attack_lab_workspace"))
    req = {"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/etc/shadow"}}}
    
    print("deterministic_stage_1:", deterministic_stage_1(req))
    
    s = {
        "name": "Out-of-scope file read",
        "type": "attack",
        "steps": [
            {"type": "mcp", "req": req}
        ]
    }
    dec, layer, lat, ep = await engine.simulate_with_airlock(s)
    print("simulate_with_airlock:", dec, layer)

asyncio.run(run())
