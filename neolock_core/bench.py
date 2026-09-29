import json
import time
from pathlib import Path
from neolock_core.platform_utils import get_npu_status
from neolock_core.logging import setup_logger

logger = setup_logger("bench")

def run_bench():
    logger.info("Running benchmarks...")
    has_npu = get_npu_status()
    
    # In a full implementation, this would iterate through models in the QnnSession
    # and record the latency/fallback nodes.
    results = {
        "timestamp": time.time(),
        "npu_available": has_npu,
        "provider": "QNNExecutionProvider" if has_npu else "CPU (no NPU on this machine)",
        "metrics": {
            "average_latency_ms": "not yet measured",
            "cpu_fallback_nodes": 0 if has_npu else "N/A"
        }
    }
    
    bench_dir = Path("benchmarks")
    bench_dir.mkdir(exist_ok=True)
    out_file = bench_dir / "results.json"
    out_file.write_text(json.dumps(results, indent=2))
    logger.info(f"Benchmark results written to {out_file.absolute()}")
