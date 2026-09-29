import subprocess
import sys

p = subprocess.Popen([sys.executable, '-m', 'neolock_core.mcp_proxy'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = p.communicate(b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file"}}\n')
print('OUT:', out.decode('utf-8', errors='replace'))
print('ERR:', err.decode('utf-8', errors='replace'))
