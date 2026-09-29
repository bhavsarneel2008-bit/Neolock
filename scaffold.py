import os
from pathlib import Path

dirs = [
    "neolock_core",
    "npu_engine/models",
    "attack_lab/payloads",
    "benchmarks",
    "ui",
    "docs",
    "tests/test_neolock_core",
    "tests/test_npu_engine",
    "tests/test_attack_lab",
    "scripts",
]

files = {
    "pyproject.toml": """[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "neolock"
version = "0.1.0"
description = "An on-device security layer for local AI agents on Snapdragon X Series Windows-on-ARM PCs."
requires-python = ">=3.11"
dependencies = [
    "onnxruntime",
    "pytest",
]

[project.scripts]
neolock = "neolock_core.mcp_proxy:main"
neolock-mcp-proxy = "neolock_core.mcp_proxy:main"
""",
    "README.md": """# Neolock
An on-device security layer for local AI agents on Snapdragon X Series Windows-on-ARM PCs. It is a transparent MCP (JSON-RPC over stdio) proxy that enforces trust capsules, taint tracking, NPU-accelerated risk scoring, canary tripwires, a tamper-evident ledger and rollback.

## Non-Negotiable Rules
1. NEVER fabricate results. If unmeasured, show "not yet measured".
2. Platform: Windows 11 ARM64. Runtime = native ARM64 Python 3.11+. 
3. NPU: ONNX Runtime with the QNN Execution Provider (QnnHtp.dll).
4. Fail closed. All model output is untrusted. No network calls at runtime, no telemetry.
5. The attack lab is simulation only.
6. Type hints, pytest tests per module, small modules, structured logging.
7. After each phase: run tests, print an acceptance checklist, and list anything unverified or assumed.
""",
    "neolock_core/__init__.py": "",
    "neolock_core/mcp_proxy.py": """def main():\n    pass\n""",
    "neolock_core/capsule.py": "",
    "neolock_core/vault.py": "",
    "neolock_core/gatekeeper.py": "",
    "neolock_core/supervisor.py": "",
    "neolock_core/ledger.py": "",
    "neolock_core/rollback.py": "",
    "npu_engine/__init__.py": "",
    "npu_engine/qnn_session.py": "",
    "npu_engine/export_and_quantize.py": "",
    "npu_engine/models/__init__.py": "",
    "attack_lab/__init__.py": "",
    "attack_lab/replay_engine.py": "",
    "attack_lab/payloads/__init__.py": "",
    "benchmarks/__init__.py": "",
    "benchmarks/reproduce_qnn.py": "",
    "tests/__init__.py": "",
    "tests/test_neolock_core/__init__.py": "",
    "tests/test_npu_engine/__init__.py": "",
    "tests/test_attack_lab/__init__.py": "",
}

for d in dirs:
    os.makedirs(d, exist_ok=True)

for path_str, content in files.items():
    p = Path(path_str)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)

print("Scaffolding complete.")
