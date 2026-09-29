import asyncio
from neolock_core.capsule import evaluate_tool_call, ACTIVE_CAPSULE, looks_like_path_or_url, is_safe_path, is_subpath

req = {"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/etc/shadow"}}}
val = "/etc/shadow"

print("looks like:", looks_like_path_or_url(val))
is_safe, canonical, reason = is_safe_path(val)
print("is_safe:", is_safe, canonical, reason)

print("allowed_dirs:", ACTIVE_CAPSULE.allowed_dirs)
if is_safe:
    for a in ACTIVE_CAPSULE.allowed_dirs:
        print("is_subpath:", is_subpath(canonical, a), "for", a)

print("Final evaluate_tool_call:", evaluate_tool_call(req, ACTIVE_CAPSULE))
