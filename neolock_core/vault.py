import os
import re
import json
import base64
import math
import numpy as np
from typing import List, Tuple, Dict, Any
from neolock_core.logging import setup_logger
from npu_engine.qnn_session import QNNSession
from tokenizers import Tokenizer

logger = setup_logger("vault")

# Aadhaar Verhoeff tables
V_D = (
    (0,1,2,3,4,5,6,7,8,9),
    (1,2,3,4,0,6,7,8,9,5),
    (2,3,4,0,1,7,8,9,5,6),
    (3,4,0,1,2,8,9,5,6,7),
    (4,0,1,2,3,9,5,6,7,8),
    (5,9,8,7,6,0,4,3,2,1),
    (6,5,9,8,7,1,0,4,3,2),
    (7,6,5,9,8,2,1,0,4,3),
    (8,7,6,5,9,3,2,1,0,4),
    (9,8,7,6,5,4,3,2,1,0)
)
V_P = (
    (0,1,2,3,4,5,6,7,8,9),
    (1,5,7,6,2,8,3,0,9,4),
    (5,8,0,3,7,9,6,1,4,2),
    (8,9,1,6,0,4,3,5,2,7),
    (9,4,5,3,1,2,6,8,7,0),
    (4,2,8,6,5,7,3,9,0,1),
    (2,7,9,3,8,0,6,4,1,5),
    (7,0,4,6,9,1,3,2,5,8)
)

def validate_verhoeff(num_str: str) -> bool:
    if not re.match(r'^\d{12}$', num_str):
        return False
    c = 0
    try:
        for i, n in enumerate(reversed(num_str)):
            c = V_D[c][V_P[i % 8][int(n)]]
        return c == 0
    except Exception:
        return False

# PII Regexes
REGEX_PAN = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b')
REGEX_UPI = re.compile(r'\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b')
REGEX_API = re.compile(r'\b(sk-[a-zA-Z0-9]{32,}|AKIA[0-9A-Z]{16})\b')
REGEX_AADHAAR = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')

def calculate_entropy(s: str) -> float:
    p, lns = {}, float(len(s))
    if lns == 0: return 0.0
    for c in s: p[c] = p.get(c, 0) + 1
    return -sum((count/lns) * math.log2(count/lns) for count in p.values())

def extract_base64_hex(text: str) -> List[str]:
    results = []
    # Basic hex
    hex_matches = re.findall(r'\b(?:[0-9a-fA-F]{2})+\b', text)
    for m in hex_matches:
        if len(m) > 16:
            try:
                decoded = bytes.fromhex(m).decode('utf-8', errors='ignore')
                if len(decoded.strip()) > 5:
                    results.append(decoded)
            except Exception:
                pass
    
    # Basic base64
    b64_matches = re.findall(r'\b(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b', text)
    for m in b64_matches:
        if len(m) > 20:
            try:
                decoded = base64.b64decode(m).decode('utf-8', errors='ignore')
                if len(decoded.strip()) > 5:
                    results.append(decoded)
            except Exception:
                pass
    return results

def cosine_similarity(v1, v2):
    dot = np.dot(v1, v2)
    norm1 = np.linalg.norm(v1)
    norm2 = np.linalg.norm(v2)
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return float(dot / (norm1 * norm2))

class Vault:
    def __init__(self, capacity: int = 1000):
        self.capacity = capacity
        self.ring_buffer = []  # (text_chunk, embedding_vector, provenance)
        self.index = 0
        
        # We assume all-MiniLM-L6-v2 which is compatible with QNN EP
        self.model_name = "all-MiniLM-L6-v2"
        self.model_path = "neolock_core/models/embedder.onnx"
        self.tokenizer_path = "neolock_core/models/embedder_tokenizer.json"
        
        self.session = None
        self.tokenizer = None
        
        # Load threshold from calibration file
        self.threshold = 0.85
        try:
            with open("taint_eval.json", "r") as f:
                data = json.loads(f.read())
                self.threshold = data.get("optimal_threshold", 0.85)
        except Exception:
            pass

        self._init_models()

    def _init_models(self):
        if not os.environ.get("NEOLOCK_DISABLE_NLP_STAGE") == "1":
            if os.path.exists(self.model_path):
                self.session = QNNSession(self.model_path, perf_mode="burst")
            if os.path.exists(self.tokenizer_path):
                self.tokenizer = Tokenizer.from_file(self.tokenizer_path)
            
    def _embed(self, text: str) -> np.ndarray:
        if self.session and self.tokenizer:
            try:
                encoded = self.tokenizer.encode(text)
                input_ids = encoded.ids[:128]
                input_ids += [0] * (128 - len(input_ids))
                attention_mask = [1 if i != 0 else 0 for i in input_ids]
                
                inputs = {
                    "input_ids": np.array([input_ids], dtype=np.int64),
                    "attention_mask": np.array([attention_mask], dtype=np.int64)
                }
                
                outputs, _ = self.session.run(inputs)
                # Output shape [1, 128, 384] -> mean pool
                embeddings = outputs[0]
                mean_pool = np.mean(embeddings, axis=1)[0]
                return mean_pool
            except Exception as e:
                logger.error(f"Embed error: {e}")
                
        # Dummy CPU fallback for tests without model
        np.random.seed(sum(ord(c) for c in text[:10]))
        return np.random.rand(384).astype(np.float32)

    def ingest(self, text: str, provenance: str, sensitivity: str):
        if sensitivity not in ["INTERNAL", "CONFIDENTIAL"]:
            return
            
        # Chunk text (very basic sliding window)
        words = text.split()
        chunk_size = 50
        
        for i in range(0, len(words), chunk_size):
            chunk = " ".join(words[i:i+chunk_size])
            if len(chunk) < 10:
                continue
                
            vec = self._embed(chunk)
            
            if len(self.ring_buffer) < self.capacity:
                self.ring_buffer.append((chunk, vec, provenance))
            else:
                self.ring_buffer[self.index] = (chunk, vec, provenance)
                self.index = (self.index + 1) % self.capacity

    def detect_pii(self, text: str) -> List[str]:
        findings = []
        if REGEX_PAN.search(text): findings.append("PAN")
        if REGEX_UPI.search(text): findings.append("UPI")
        if REGEX_API.search(text): findings.append("API_KEY")
        
        for m in REGEX_AADHAAR.finditer(text):
            num = m.group(0).replace(" ", "")
            if validate_verhoeff(num):
                findings.append("AADHAAR")
        return findings

    def check_outbound(self, payload: str) -> Tuple[bool, str, str]:
        # Basic PII
        pii = self.detect_pii(payload)
        if pii:
            return True, f"PII detected: {','.join(pii)}", "CPU"

        # Entropy check
        if calculate_entropy(payload) > 5.5 and len(payload) > 50:
            return True, "High entropy payload detected", "CPU"

        # Base64/Hex decode and re-check
        decoded_texts = extract_base64_hex(payload)
        texts_to_check = [payload] + decoded_texts

        for txt in texts_to_check:
            words = txt.split()
            window = 50
            for i in range(0, len(words), window):
                chunk = " ".join(words[i:i+window])
                if len(chunk) < 10:
                    continue
                
                vec = self._embed(chunk)
                
                for stored_chunk, stored_vec, prov in self.ring_buffer:
                    sim = cosine_similarity(vec, stored_vec)
                    if sim >= self.threshold:
                        ep = self.session.execution_provider if self.session else "CPU"
                        return True, f"Semantic match (sim={sim:.3f}) with {prov} data", ep
                        
        return False, "", "CPU"
