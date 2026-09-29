import platform
import ctypes
import os
import subprocess
from pathlib import Path
from neolock_core.logging import setup_logger
from neolock_core.platform_utils import is_windows, is_snapdragon

logger = setup_logger("doctor")

def _check_ort():
    """Runs ORT checks in a subprocess to avoid hard crashes (e.g., Access Violation)."""
    code = '''
try:
    import onnxruntime as ort
    print(ort.__version__)
    print(",".join(ort.get_available_providers()))
except Exception as e:
    print("ERROR")
    print(str(e))
'''
    import sys
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2 and lines[0] != "ERROR":
                return True, lines[0], lines[1].split(',')
        return False, f"Failed or crashed. RC={result.returncode}", []
    except Exception as e:
        return False, f"Failed to run subprocess: {e}", []

def run_doctor():
    print("=== Neolock System Doctor ===\n")
    all_passed = True

    # OS / Arch check
    os_name = platform.system()
    os_release = platform.release()
    arch = platform.machine()
    print(f"OS/Arch: {os_name} {os_release} {arch}")
    
    if is_snapdragon():
        print("[PASS] Windows 11 ARM64 detected.")
    else:
        print("[INFO] Not running on Snapdragon X. NPU: not available on this machine.")
        print("  Hint: Development mode enabled. Operations will fall back to CPU.")
    
    if not is_windows():
        print("[WARN] Non-Windows OS. Ledger protection is using a local key file. Do not use in production.")

    # 2. Python architecture
    py_arch = platform.architecture()[0]
    is_native_py = (arch.lower() in ["arm64", "aarch64"] and py_arch == "64bit")
    print(f"\nPython Architecture: {platform.python_version()} {py_arch}")
    
    if is_snapdragon():
        if is_native_py:
            print("[PASS] Native ARM64 Python detected.")
        else:
            print("[FAIL] Requires native ARM64 Python 3.11+.")
            print("  Hint: Ensure your Python installer was the ARM64 version, not x64 emulated.")
            all_passed = False
    else:
        print("[INFO] Python architecture check skipped (non-Snapdragon).")

    # 3 & 4. ONNX Runtime & QNN EP
    ort_ok, ort_version, providers = _check_ort()
    if ort_ok:
        print(f"\nONNX Runtime Version: {ort_version}")
        print("[PASS] ONNX Runtime is installed.")
        print(f"\nAvailable ORT Providers: {', '.join(providers)}")
        if 'QNNExecutionProvider' in providers:
            print("[PASS] QNN Execution Provider is available.")
        else:
            if is_snapdragon():
                print("[FAIL] QNN Execution Provider is missing.")
                print("  Hint: Install onnxruntime-qnn or check ORT build options.")
                all_passed = False
            else:
                print("[INFO] QNN Execution Provider is missing (expected on non-Snapdragon).")
    else:
        print("\nONNX Runtime Check:")
        print(f"[FAIL] ONNX Runtime failed to load ({ort_version}).")
        print("  Hint: Ensure onnxruntime is compatible with your architecture.")
        all_passed = False

    # 5. QnnHtp.dll loads
    print("\nQnnHtp.dll Check:")
    if is_snapdragon():
        try:
            ctypes.WinDLL("QnnHtp.dll")
            print("[PASS] QnnHtp.dll loaded successfully.")
        except Exception as e:
            print(f"[FAIL] Failed to load QnnHtp.dll.")
            print(f"  Error: {e}")
            print("  Hint: Ensure Qualcomm Neural Processing SDK is installed and QnnHtp.dll is in PATH.")
            all_passed = False
    else:
        print("[INFO] Skipped QnnHtp.dll check (non-Snapdragon).")

    # 6. Context-binary cache status
    cache_dir = Path(".neolock/cache")
    print(f"\nContext-binary Cache ({cache_dir}):")
    if cache_dir.exists() and cache_dir.is_dir():
        files = list(cache_dir.iterdir())
        if files:
            file_names = [f.name for f in files]
            print(f"[PASS] Cache exists with {len(files)} files: {', '.join(file_names)}")
        else:
            print("[FAIL] Cache directory found but empty.")
            print("  Hint: Run 'neolock bench' or model preparation to generate context binaries.")
            all_passed = False
    else:
        print("[FAIL] Cache directory not found.")
        print("  Hint: Run 'neolock bench' or model preparation to generate context binaries.")
        all_passed = False

    print("\n=== Doctor Report ===")
    if all_passed:
        print("Status: ALL CHECKS PASSED. NPU is ready.")
        logger.info("Doctor run completed successfully.")
    else:
        print("Status: SOME CHECKS FAILED. NPU may be unavailable or environment is misconfigured.")
        print("Note: In attack_lab, you can proceed in simulation mode.")
        logger.warning("Doctor run completed with failures.")
    return all_passed
