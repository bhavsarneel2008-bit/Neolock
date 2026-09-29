import time
import json
import os
import platform
from pathlib import Path
from neolock_core.logging import setup_logger
from neolock_core.platform_utils import get_npu_status

logger = setup_logger("qnn_session")

def _safe_import_ort():
    """Import ONNX Runtime gracefully, preventing hard process crashes (exit code 1 without traceback)."""
    import sys
    import subprocess
    try:
        # Test if it hard-crashes by running it in a subprocess first
        res = subprocess.run(
            [sys.executable, "-c", "import onnxruntime"],
            capture_output=True,
            timeout=5
        )
        if res.returncode != 0:
            logger.warning(f"onnxruntime hard-crashed with exit code {res.returncode}. Disabling ONNX support.")
            return None
            
        import onnxruntime as ort
        return ort
    except Exception as e:
        logger.error(f"Failed to import onnxruntime: {e}")
        return None

class QNNSession:
    def __init__(self, model_path: str, cache_dir: str = ".neolock/cache",
                 perf_mode: str = "burst", use_cpu_baseline: bool = False):
        self.model_path = Path(model_path)
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.perf_mode = perf_mode
        self.use_cpu_baseline = use_cpu_baseline
        
        self.npu_sess = None
        self.cpu_sess = None
        self.last_run_info = {}
        self.npu_available = get_npu_status()
        
        ort = _safe_import_ort()
        if not ort:
            return

        model_name = self.model_path.stem
        ctx_binary = self.cache_dir / f"{model_name}_{perf_mode}.bin"
        
        so = ort.SessionOptions()
        # Profiling is needed to determine fallback nodes per Rule
        so.enable_profiling = True 
        
        if self.npu_available:
            providers = ort.get_available_providers()
            if "QNNExecutionProvider" not in providers:
                logger.info("QNNExecutionProvider not available in ort.get_available_providers().")
                self.npu_sess = None
            else:
                qnn_options = {
                    "backend_path": "QnnHtp.dll",
                    "htp_performance_mode": perf_mode,
                    "ep.context_enable": "1",
                    "ep.context_file_path": str(ctx_binary),
                    "disable_cpu_ep_fallback": "1"
                }
                
                import ctypes
                dll_ok = False
                try:
                    ctypes.WinDLL("QnnHtp.dll")
                    dll_ok = True
                except Exception as e:
                    logger.warning(f"QnnHtp.dll failed to load: {e}. Skipping QNN session.")
                    self.npu_sess = None

                if dll_ok:
                    try:
                        self.npu_sess = ort.InferenceSession(
                            str(self.model_path), 
                            sess_options=so,
                            providers=["QNNExecutionProvider", "CPUExecutionProvider"],
                            provider_options=[qnn_options, {}]
                        )
                        logger.info("NPU session created successfully.")
                    except Exception as e:
                        logger.warning(f"Failed to create QNN session: {e}. QNN EP might be unavailable.")
                        self.npu_sess = None
        else:
            logger.info("NPU is not available on this machine. Skipping NPU session creation.")

        if self.use_cpu_baseline or not self.npu_sess:
            cpu_so = ort.SessionOptions()
            cpu_so.enable_profiling = True
            self.cpu_sess = ort.InferenceSession(
                str(self.model_path),
                sess_options=cpu_so,
                providers=["CPUExecutionProvider"]
            )

    def run(self, inputs, use_cpu: bool = False):
        sess = self.cpu_sess if use_cpu else self.npu_sess
        if not sess:
            raise RuntimeError("Requested session is not available.")
            
        start_t = time.perf_counter()
        outputs = sess.run(None, inputs)
        end_t = time.perf_counter()
        latency = (end_t - start_t) * 1000
        
        prof_file = sess.end_profiling()
        cpu_nodes = 0
        total_nodes = 0
        actual_ep = "CPU" if use_cpu else "QNN"
        if not self.npu_available and not use_cpu:
            actual_ep = "CPU (no NPU on this machine)"
        
        # Re-enable profiling for the next run since end_profiling() stops it
        ort = _safe_import_ort()
        if ort:
            sess_options = sess.get_session_options()
            sess_options.enable_profiling = True
        
        # Analyze profiling data for fallback nodes
        if prof_file and os.path.exists(prof_file):
            try:
                with open(prof_file, 'r') as f:
                    prof_data = json.load(f)
                for event in prof_data:
                    if event.get("cat") == "Kernel":
                        total_nodes += 1
                        args = event.get("args", {})
                        if args.get("provider") == "CPUExecutionProvider":
                            cpu_nodes += 1
                os.remove(prof_file)
            except Exception as e:
                logger.error(f"Failed to parse profiling data: {e}")
        
        self.last_run_info = {
            "latency_ms": latency,
            "fallback_nodes": cpu_nodes,
            "total_nodes": total_nodes,
            "actual_ep": actual_ep
        }
        logger.info(f"Run stats - Latency: {latency:.2f}ms | Total Nodes: {total_nodes} | CPU Fallback: {cpu_nodes} | Actual EP: {actual_ep}")
        
        return outputs, self.last_run_info

    @property
    def execution_provider(self):
        if hasattr(self, "last_run_info") and self.last_run_info:
            ep = self.last_run_info.get("actual_ep", "CPU")
            fallback = self.last_run_info.get("fallback_nodes", 0)
            if fallback > 0:
                return f"{ep} (with {fallback} CPU fallback nodes)"
            return ep
        return "QNN" if self.npu_sess else "CPU"
