import platform
import os
from pathlib import Path

def is_windows() -> bool:
    return platform.system() == "Windows"

def is_snapdragon() -> bool:
    return is_windows() and platform.machine().lower() in ["arm64", "aarch64"]

def get_npu_status() -> bool:
    if not is_snapdragon():
        return False
    try:
        import onnxruntime as ort
        return 'QNNExecutionProvider' in ort.get_available_providers()
    except Exception:
        return False

# Ledger Key Protection and NTFS ADS Windows implementations
if is_windows():
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def protect_data(data: bytes) -> bytes:
        crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(DATA_BLOB), ctypes.c_wchar_p, ctypes.POINTER(DATA_BLOB),
            ctypes.c_void_p, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(DATA_BLOB)
        ]
        crypt32.CryptProtectData.restype = ctypes.wintypes.BOOL
        
        in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.c_char_p(data), ctypes.POINTER(ctypes.c_byte)))
        out_blob = DATA_BLOB()
        if crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
            res = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            kernel32 = ctypes.WinDLL("kernel32.dll")
            kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            kernel32.LocalFree.restype = ctypes.c_void_p
            kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))
            return res
        raise RuntimeError("CryptProtectData failed")

    def unprotect_data(data: bytes) -> bytes:
        crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(DATA_BLOB), ctypes.c_wchar_p, ctypes.POINTER(DATA_BLOB),
            ctypes.c_void_p, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(DATA_BLOB)
        ]
        crypt32.CryptUnprotectData.restype = ctypes.wintypes.BOOL
        
        in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.c_char_p(data), ctypes.POINTER(ctypes.c_byte)))
        out_blob = DATA_BLOB()
        if crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
            res = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            kernel32 = ctypes.WinDLL("kernel32.dll")
            kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            kernel32.LocalFree.restype = ctypes.c_void_p
            kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))
            return res
        raise RuntimeError("CryptUnprotectData failed")
        
    def write_ads(file_path: str, stream_name: str, data: str):
        with open(f"{file_path}:{stream_name}", "w", encoding="utf-8") as f:
            f.write(data)

    def read_ads(file_path: str, stream_name: str) -> str:
        with open(f"{file_path}:{stream_name}", "r", encoding="utf-8") as f:
            return f.read()

else:
    def protect_data(data: bytes) -> bytes:
        # Dummy local key protection for cross-platform development
        key_file = Path(".neolock/dev_key.bin")
        if not key_file.exists():
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_bytes(os.urandom(32))
            os.chmod(key_file, 0o600)
        key = key_file.read_bytes()
        # Simple XOR for dummy protection
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    def unprotect_data(data: bytes) -> bytes:
        return protect_data(data) # XOR is symmetric
        
    def write_ads(file_path: str, stream_name: str, data: str):
        # Stub for Linux/macOS
        with open(f"{file_path}_{stream_name}.ads", "w", encoding="utf-8") as f:
            f.write(data)

    def read_ads(file_path: str, stream_name: str) -> str:
        with open(f"{file_path}_{stream_name}.ads", "r", encoding="utf-8") as f:
            return f.read()
