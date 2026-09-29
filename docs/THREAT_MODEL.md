# Threat Model

## In Scope
Airlock is designed to protect local user environments from the following threats posed by autonomous AI agents:
1. **Prompt Injection / Jailbreaks**: An attacker embeds malicious instructions in an untrusted file, webpage, or email (e.g., `RETRIEVED_DOC`), hijacking the agent's behavior to execute destructive commands.
2. **Data Exfiltration**: An agent reads confidential or internal data and attempts to send it to an external server.
3. **Out-of-Scope Access**: An agent attempts to read, modify, or delete files outside of its strictly designated workspace (Capsule).
4. **Behavioral Drift / Runaway Agents**: An agent enters a confused state, recursively spawning subprocesses, creating archives, or exhausting network resources.
5. **Ledger Tampering**: A compromised agent process attempts to cover its tracks by deleting or altering the Airlock tool execution logs.

## Out of Scope
Airlock operates as a transparent proxy for the Model Context Protocol (MCP) tool execution loop. The following are explicitly out of scope:
1. **Direct Agent Bypass**: If an agent process is intentionally written to bypass the MCP proxy and execute shell commands directly (e.g., via `os.system` in Python without using the MCP tools), Airlock cannot intercept it. We assume the agent uses the proxy for its tool calls.
2. **Host OS Compromise**: If the underlying Windows OS or kernel is compromised by other malware, Airlock cannot guarantee protection.
3. **Hardware Attacks**: Physical access to the machine or attacks on the Snapdragon Hexagon NPU firmware are out of scope.
4. **LLM Hallucinations**: Airlock does not prevent the agent from giving the user incorrect or hallucinated text responses. It only guards *tool execution*.
