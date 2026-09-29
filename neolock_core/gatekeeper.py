import os
import asyncio
import json
import numpy as np
from typing import Tuple
from tokenizers import Tokenizer
from neolock_core.logging import setup_logger
from neolock_core.capsule import ACTIVE_CAPSULE, evaluate_tool_call
from npu_engine.qnn_session import QNNSession

logger = setup_logger("gatekeeper")

MODEL_PATH = "neolock_core/models/classifier.onnx"
TOKENIZER_PATH = "neolock_core/models/tokenizer.json"

_npu_session = None
_tokenizer = None

def _get_npu_session():
    global _npu_session
    if _npu_session is None:
        if os.path.exists(MODEL_PATH):
            _npu_session = QNNSession(MODEL_PATH, perf_mode="burst")
        else:
            logger.warning(f"ONNX model not found at {MODEL_PATH}")
    return _npu_session

def _get_tokenizer():
    global _tokenizer
    if _tokenizer is None:
        if os.path.exists(TOKENIZER_PATH):
            _tokenizer = Tokenizer.from_file(TOKENIZER_PATH)
        else:
            logger.warning(f"Tokenizer not found at {TOKENIZER_PATH}")
    return _tokenizer

if os.name == 'nt':
    import ctypes
    def _prompt_user_sync(title: str, message: str, timeout_sec: int) -> bool:
        MB_YESNO = 0x04
        MB_ICONWARNING = 0x30
        MB_DEFBUTTON2 = 0x100
        MB_TOPMOST = 0x40000
        try:
            user32 = ctypes.WinDLL('user32', use_last_error=True)
            user32.MessageBoxTimeoutW.argtypes = [
                ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, 
                ctypes.c_uint, ctypes.c_ushort, ctypes.c_uint
            ]
            user32.MessageBoxTimeoutW.restype = ctypes.c_int
            
            res = user32.MessageBoxTimeoutW(
                None, message, title, 
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST, 
                0, timeout_sec * 1000
            )
            return res == 6 # IDYES
        except Exception as e:
            logger.error(f"Failed to show Windows prompt: {e}")
            return False
else:
    def _prompt_user_sync(title: str, message: str, timeout_sec: int) -> bool:
        import select
        try:
            with open('/dev/tty', 'w') as tty_out, open('/dev/tty', 'r') as tty_in:
                tty_out.write(f"\n[NEOLOCK] {title}\n{message}\nApprove? [y/N] (Timeout {timeout_sec}s): ")
                tty_out.flush()
                r, w, e = select.select([tty_in], [], [], timeout_sec)
                if r:
                    return tty_in.readline().strip().lower() == 'y'
                else:
                    tty_out.write("\nTimeout reached.\n")
                    return False
        except Exception as e:
            logger.error(f"Failed to show TTY prompt: {e}")
            return False

async def _run_nlp_stage(req: dict) -> Tuple[str, str]:
    if os.environ.get("NEOLOCK_DISABLE_NLP_STAGE") == "1":
        return "ALLOW", ""
        
    session = _get_npu_session()
    tokenizer = _get_tokenizer()
    
    if not session or not tokenizer:
        return "ALLOW", "ML Models not available"
        
    params = req.get("params", {})
    tool_name = params.get("name", "")
    tool_args = json.dumps(params.get("arguments", {}))
    provenance = req.get("provenance", "USER")
    
    text = f"[{provenance}] {tool_name} {tool_args}"
    
    encoded = tokenizer.encode(text)
    seq_len = 128
    ids = encoded.ids[:seq_len]
    mask = encoded.attention_mask[:seq_len]
    
    pad_id = tokenizer.token_to_id("[PAD]") or 0
    ids = ids + [pad_id] * (seq_len - len(ids))
    mask = mask + [0] * (seq_len - len(mask))
    
    ort_inputs = {
        "input_ids": np.array([ids], dtype=np.int64),
        "attention_mask": np.array([mask], dtype=np.int64)
    }
    
    try:
        outputs, metrics = session.run(ort_inputs)
        logger.info(f"NPU Metrics: {metrics}")
        
        logits = outputs[0][0]
        score = float(logits[1] - logits[0])
        
        if score > 2.0:
            return "BLOCK", f"High prompt injection risk detected (score: {score:.2f})"
        elif score > 0.0:
            return "ASK", f"Moderate prompt injection risk detected (score: {score:.2f})"
        else:
            return "ALLOW", ""
    except Exception as e:
        logger.error(f"Model error during Stage 2: {e}")
        return "BLOCK", f"Model error: {e}"

def deterministic_stage_1(req: dict) -> Tuple[str, str]:
    params = req.get("params", {})
    tool_name = params.get("name", "")
    
    provenance = req.get("provenance", "USER")
    if provenance in ["RETRIEVED_DOC", "WEBPAGE", "EMAIL"]:
        if tool_name in ["run_command", "bash", "python", "delete_file", "write_file"]:
            return "BLOCK", f"Untrusted provenance ({provenance}) attempting destructive tool: {tool_name}"
            
    if tool_name == "trigger_ask":
        return "ASK", "Need user approval for trigger_ask"
        
    return "ALLOW", ""

async def hook_gatekeeper(req: dict):
    # Note: capsule evaluation is already handled by hook_rules.
    # This represents the remaining Stage 1 logic.
    decision, reason = deterministic_stage_1(req)
    if decision != "ALLOW":
        return decision, reason
        
    loop = asyncio.get_running_loop()
    decision, reason = await loop.run_in_executor(None, lambda: asyncio.run(_run_nlp_stage(req)))
    
    return decision, reason

import concurrent.futures
_ask_executor = concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="GatekeeperAsk")

async def ask_user_approval(req: dict, reason: str, timeout_sec: int = 30) -> bool:
    tool_name = req.get("params", {}).get("name", "unknown")
    title = f"Neolock Gatekeeper: Tool Execution Paused"
    message = f"The agent is attempting to execute '{tool_name}'.\n\nReason for pause: {reason}\n\nDo you want to ALLOW this execution?"
    
    loop = asyncio.get_running_loop()
    approved = await loop.run_in_executor(_ask_executor, _prompt_user_sync, title, message, timeout_sec)
    
    if approved:
        logger.info(f"User approved execution of {tool_name}")
    else:
        logger.warning(f"User denied execution of {tool_name} (or timed out)")
        
    return approved
