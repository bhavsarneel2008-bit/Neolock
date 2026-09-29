import json
import asyncio
import time
from pathlib import Path
from neolock_core.logging import setup_logger

logger = setup_logger("lab")

def generate_scoreboard(summary: dict) -> str:
    md = "# Airlock Defense Lab Scoreboard\n\n"
    md += f"**Timestamp:** {summary['timestamp']}\n\n"
    md += "### Metrics\n"
    md += f"- **Attack Success Rate:** {summary['metrics']['attack_success_rate']}%\n"
    md += f"- **Benign Utility:** {summary['metrics']['benign_utility']}%\n"
    md += f"- **False Positive Rate:** {summary['metrics']['false_positive_rate']}%\n\n"
    
    md += "### Scenarios\n"
    md += "| Scenario Name | Type | Decision | Enforcing Layer | Latency (ms) | Execution Provider |\n"
    md += "|---|---|---|---|---|---|\n"
    
    for s in summary["scenarios"]:
        md += f"| {s['name']} | {s['type']} | {s['decision']} | {s['layer']} | {s['latency_ms']} | {s['ep']} |\n"
        
    return md

def run_lab():
    logger.info("Running attack lab simulations...")
    from attack_lab.replay_engine import ReplayEngine
    
    workspace = Path.cwd() / "attack_lab_workspace"
    engine = ReplayEngine(workspace)
    
    summary = asyncio.run(engine.run())
    
    lab_dir = Path.cwd() / "attack_lab"
    lab_dir.mkdir(exist_ok=True)
    
    out_json = lab_dir / "results.json"
    out_json.write_text(json.dumps(summary, indent=2))
    logger.info(f"Attack lab results written to {out_json.absolute()}")
    
    scoreboard = generate_scoreboard(summary)
    out_md = lab_dir / "SCOREBOARD.md"
    out_md.write_text(scoreboard)
    logger.info(f"Scoreboard generated at {out_md.absolute()}")
    
    print("\n" + scoreboard)

if __name__ == "__main__":
    run_lab()
