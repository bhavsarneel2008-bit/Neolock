import argparse
from neolock_core.doctor import run_doctor
from neolock_core.mcp_proxy import run_proxy

from neolock_core.bench import run_bench
from neolock_core.lab import run_lab

def run_ui():
    from neolock_core.dashboard import start_server
    start_server()

def main():
    parser = argparse.ArgumentParser(description="Neolock CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("doctor", help="Run system diagnostics for NPU and environment")
    subparsers.add_parser("proxy", help="Run the MCP proxy")
    subparsers.add_parser("lab", help="Run the attack lab simulation")
    subparsers.add_parser("bench", help="Run benchmarks")
    subparsers.add_parser("ui", help="Start the web UI")

    args = parser.parse_args()

    if args.command == "doctor":
        run_doctor()
    elif args.command == "proxy":
        run_proxy()
    elif args.command == "lab":
        run_lab()
    elif args.command == "bench":
        run_bench()
    elif args.command == "ui":
        run_ui()

if __name__ == "__main__":
    main()
