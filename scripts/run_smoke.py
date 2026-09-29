import os
import numpy as np
from pathlib import Path
from neolock_core.logging import setup_logger
from export_and_quantize import (
    export_model, quantize_qdq, get_calibration_reader_class, evaluate_parity, compile_via_qai_hub
)
from npu_engine.qnn_session import QNNSession

logger = setup_logger("smoke_test")

def main():
    logger.info("Starting smoke test for QNN export and inference...")
    
    try:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except (ImportError, OSError) as e:
        logger.error(f"Failed to import ML libraries (transformers/torch): {e}")
        logger.error("Failure is expected on incompatible architectures (e.g., missing DLLs).")
        return

    model_id = "prajjwal1/bert-tiny" # Small model for fast export
    model_dir = Path(".neolock/smoke_test")
    model_dir.mkdir(parents=True, exist_ok=True)
    
    fp32_path = str(model_dir / "bert_tiny_fp32.onnx")
    qdq_path = str(model_dir / "bert_tiny_qdq.onnx")
    
    logger.info(f"Loading {model_id}...")
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    
    if not os.path.exists(fp32_path):
        export_model(model, tokenizer, fp32_path, seq_len=128)
        
    if not os.path.exists(qdq_path):
        ReaderClass = get_calibration_reader_class()
        calib_reader = ReaderClass(dataset_size=1, seq_len=128)
        quantize_qdq(fp32_path, qdq_path, calib_reader, mode="W8A8")
        
    evaluate_parity(fp32_path, qdq_path)
    compile_via_qai_hub(qdq_path)
    
    # Run inference tests
    logger.info("Running NPU Session (which might fail/fallback if NPU unavailable)...")
    qnn = QNNSession(qdq_path, use_cpu_baseline=True)
    
    dummy_input = {
        "input_ids": np.random.randint(0, 1000, (1, 128), dtype=np.int64),
        "attention_mask": np.ones((1, 128), dtype=np.int64)
    }
    
    # Test CPU
    logger.info("Testing CPU Baseline...")
    out_cpu, stats_cpu = qnn.run(dummy_input, use_cpu=True)
    
    # Test NPU
    if qnn.npu_sess:
        logger.info("Testing NPU Session...")
        out_npu, stats_npu = qnn.run(dummy_input, use_cpu=False)
        if stats_npu["fallback_nodes"] > 0:
            logger.warning(f"Model ran on NPU but {stats_npu['fallback_nodes']} nodes fell back to CPU.")
        else:
            logger.info("Model ran strictly on NPU with 0 fallback nodes.")
    else:
        logger.error("NPU Session could not be created. Failure is expected on x64 or misconfigured machines.")

if __name__ == "__main__":
    main()
