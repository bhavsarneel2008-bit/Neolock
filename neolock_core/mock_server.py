import sys
import json

def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            req_data = json.loads(line)
        except json.JSONDecodeError:
            continue
            
        requests = req_data if isinstance(req_data, list) else [req_data]
        responses = []
        
        for req in requests:
            if not isinstance(req, dict):
                continue
            req_id = req.get("id")
            method = req.get("method")
            
            if req_id is not None:
                responses.append({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"status": "success", "method": method, "mock": True}
                })
        
        if responses:
            if isinstance(req_data, list):
                sys.stdout.write(json.dumps(responses) + "\n")
            else:
                sys.stdout.write(json.dumps(responses[0]) + "\n")
            sys.stdout.flush()
        elif method == "notifications/ping":
            # Just ignore notifications for now
            pass

if __name__ == "__main__":
    main()
