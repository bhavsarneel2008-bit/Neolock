# Limitations & Known Evasions

While Airlock provides robust deterministic and ML-based guardrails, the following limitations exist:

## Known Evasions
1. **Encoding Evasions**: The Vault DLP uses simple entropy and heuristic checks for base64/hex encoding. Advanced or custom encoding schemes (e.g., custom XOR cyphers, steganography) applied by a rogue agent could bypass the semantic sliding-window similarity checks and exfiltrate data.
2. **Translation**: If an agent reads a sensitive file in English and translates it to French before exfiltration, the cosine similarity of the QNN embeddings may drop below the blocking threshold, allowing the data to leak.
3. **Pacing Attacks**: The Supervisor tracks behavioral drift using an Exponential Moving Average ($R_t$). An agent could intentionally pace its destructive actions over a long period (e.g., one highly suspicious action per hour) to allow the EMA decay factor to lower the score, preventing it from crossing the 0.85 quarantine threshold.

## Unverified Claims
- **Prompt Injection Classifier Accuracy**: The HuggingFace prompt injection classifier runs on static 1x128 shape inputs. Its recall on highly advanced or domain-specific prompt injections has not been exhaustively evaluated on this NPU implementation.
- **NPU Power Draw**: While inference on the Hexagon NPU is inherently more efficient than CPU, the actual full-system battery discharge curve over a 10-minute continuous agent run has not yet been precisely measured and validated in hardware.
