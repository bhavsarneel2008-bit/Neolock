import os
import re
import ctypes
import urllib.parse
import unicodedata
from enum import Enum
from pathlib import Path
from typing import List, Tuple, Any
from pydantic import BaseModel

class Sensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"

class TrustCapsule(BaseModel):
    agent_id: str
    allowed_dirs: List[str]
    blocked_dirs: List[str]
    network_locked: bool
    max_files: int
    max_sensitivity: Sensitivity
    ttl_expiry: float
    allow_shell: bool = False

ACTIVE_CAPSULE = TrustCapsule(
    agent_id="default",
    allowed_dirs=[str(Path.cwd().resolve())],
    blocked_dirs=[],
    network_locked=False,
    max_files=1000,
    max_sensitivity=Sensitivity.PUBLIC,
    ttl_expiry=0.0,
    allow_shell=False
)

def resolve_nearest_existing(path_str: str) -> Path:
    p = Path(path_str).absolute()
    parts = []
    while not p.exists() and p.parent != p:
        parts.insert(0, p.name)
        p = p.parent
    
    if p.exists():
        p = p.resolve()
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
            kernel32.GetLongPathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
            kernel32.GetLongPathNameW.restype = ctypes.c_uint32
            
            buf = ctypes.create_unicode_buffer(32768)
            res = kernel32.GetLongPathNameW(str(p), buf, 32768)
            if res != 0 and res <= 32768:
                p = Path(buf.value)
                
    for part in parts:
        p = p / part
    return p

def is_safe_path(raw_path: str) -> Tuple[bool, str, str]:
    if "\x00" in raw_path:
        return False, "", "Null byte detected"
        
    decoded = urllib.parse.unquote(raw_path)
    if decoded != raw_path:
        raw_path = decoded
        
    normalized = unicodedata.normalize('NFKC', raw_path)
    if normalized != raw_path:
        return False, "", "Unicode lookalike/NFKC normalization required"
        
    # Standardize slashes
    clean_parts = [p for p in raw_path.replace('\\', '/').split('/') if p]
    
    if ".." in clean_parts:
        return False, "", "Path traversal detected"

    if re.search(r'%[A-Za-z0-9_]+%', raw_path) or "~" in raw_path:
        return False, "", "Environment variables or home dir shorthand detected"

    if raw_path.startswith("file://"):
        return False, "", "file:// URI detected"

    if os.name == "nt":
        if raw_path.startswith("\\\\"):
            return False, "", "UNC or device path detected"
            
        for part in clean_parts:
            name = part.split('.')[0].upper()
            if name in ["CON", "PRN", "AUX", "NUL"] or re.match(r'^(COM|LPT)[1-9]$', name):
                return False, "", "Reserved device name detected"

        for part in clean_parts:
            if part not in [".", ".."] and (part.endswith(".") or part.endswith(" ")):
                return False, "", "Trailing dot or space in path part"

        if "::$DATA" in raw_path.upper():
            return False, "", "NTFS ADS ::$DATA detected"
            
        drive, tail = os.path.splitdrive(raw_path)
        if ":" in tail:
            return False, "", "NTFS Alternate Data Stream detected"
            
    try:
        canonical = resolve_nearest_existing(raw_path)
    except Exception as e:
        return False, "", f"Resolution error: {e}"
        
    if os.name == "nt":
        canonical = Path(str(canonical).lower())
        
    return True, str(canonical), ""

def looks_like_path_or_url(s: str) -> bool:
    if not isinstance(s, str) or len(s) > 1024 or len(s) == 0:
        return False
        
    decoded = urllib.parse.unquote(s)
    
    for check_s in (s, decoded):
        if "\x00" in check_s:
            return True
        if re.match(r'^(https?|ftp|ws|wss|file)://', check_s, re.IGNORECASE):
            return True
        if re.match(r'^([A-Za-z]:[\\/]|/)', check_s):
            return True
        if re.match(r'^\.\.?([\\/]|$)', check_s):
            return True
        if "\\" in check_s or "/" in check_s:
            return True
        if re.search(r'\.[a-zA-Z0-9]{1,5}(\x00|\s|\.)*$', check_s):
            return True
        if "~" in check_s or "::$DATA" in check_s.upper() or re.search(r':[^\\/]+$', check_s):
            return True
        if re.search(r'%[A-Za-z0-9_]+%', check_s) or re.search(r'(?i)(%2e%2e|%2f|%5c|%3a)', check_s):
            return True
        if os.name == "nt" and re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$', check_s, re.IGNORECASE):
            return True
            
    return False

def is_subpath(path_str: str, parent_str: str) -> bool:
    try:
        path_obj = Path(path_str)
        parent_obj = Path(parent_str)
        if os.name == "nt":
            path_obj = Path(str(path_obj).lower())
            parent_obj = Path(str(parent_obj).lower())
        return os.path.commonpath([str(path_obj), str(parent_obj)]) == str(parent_obj)
    except ValueError:
        return False

def check_value(val: str, capsule: TrustCapsule) -> Tuple[str, str, str]:
    if capsule.network_locked and re.match(r'^(https?|ftp|ws|wss)://', val, re.IGNORECASE):
        return "BLOCK", "NET1", f"Network access locked. URL detected: {val}"
        
    if looks_like_path_or_url(val):
        is_safe, canonical, reason = is_safe_path(val)
        if not is_safe:
            return "BLOCK", "P1", f"Unsafe path detected: {reason}"
            
        if canonical:
            for b in capsule.blocked_dirs:
                if is_subpath(canonical, b):
                    return "BLOCK", "P2", f"Path intersects blocked directory: {b}"
                    
            allowed = False
            for a in capsule.allowed_dirs:
                if is_subpath(canonical, a):
                    allowed = True
                    break
                    
            if not allowed:
                return "ASK", "P3", f"Path not in allowed directories: {val}"
                
    return "ALLOW", "", ""

def scan_arguments(args: Any, capsule: TrustCapsule) -> Tuple[str, str, str]:
    if isinstance(args, str):
        return check_value(args, capsule)
    elif isinstance(args, list):
        for item in args:
            decision, rule, reason = scan_arguments(item, capsule)
            if decision != "ALLOW":
                return decision, rule, reason
    elif isinstance(args, dict):
        for k, v in args.items():
            decision, rule, reason = scan_arguments(v, capsule)
            if decision != "ALLOW":
                return decision, rule, reason
    return "ALLOW", "", ""

KNOWN_TOOLS = ["read_file", "write_file", "list_dir", "search_web", "git", "run_script"]
SHELL_TOOLS = ["bash", "cmd", "powershell", "sh", "exec", "shell", "run_command"]

def evaluate_tool_call(req: dict, capsule: TrustCapsule) -> Tuple[str, str, str]:
    method = req.get("method")
    if method != "tools/call":
        return "ALLOW", "", ""
        
    params = req.get("params", {})
    tool_name = params.get("name", "")
    args = params.get("arguments", {})
    
    if capsule.network_locked and tool_name in ["fetch", "curl", "wget", "request", "http_get", "browser", "search_web"]:
        return "BLOCK", "NET2", f"Network access locked. Network tool requested: {tool_name}"
        
    if tool_name in SHELL_TOOLS:
        if not capsule.allow_shell:
            return "ASK", "S1", f"Shell execution requires explicit approval for tool: {tool_name}"
            
    if tool_name not in KNOWN_TOOLS and tool_name not in SHELL_TOOLS:
        return "ASK", "T1", f"Unknown tool requested: {tool_name}"
        
    decision, rule, reason = scan_arguments(args, capsule)
    return decision, rule, reason
