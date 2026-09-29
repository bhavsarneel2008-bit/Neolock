# Neolock Snapdragon X (Windows-on-ARM) Deployment Checklist

This project was developed on a non-Snapdragon machine and leverages platform abstractions. Before deploying to real Snapdragon X Series silicon, the following components must be verified on-device.

## 1. NPU Engine (ONNX Runtime QNN EP)
- [ ] **QNN HTP Backend**: Verify `QnnHtp.dll` loads correctly on the Snapdragon device.
- [ ] **Context Binary Caching**: Ensure `ep.context_enable` and `ep.context_file_path` correctly produce and load the cached HTP binary to skip JIT compilation.
- [ ] **Zero CPU Fallback**: Verify that `session.disable_cpu_ep_fallback="1"` properly throws an error or forces the model entirely onto the NPU without falling back to CPU ops.
- [ ] **Latency and Profiling**: Confirm that latency metrics returned by the `QnnSession` are accurate and reflect NPU acceleration.

## 2. Qualcomm AI Hub (x64 Tooling)
- [ ] **Compilation/Profiling Path**: The optional `submit_compile_job` and `submit_profile_job` paths currently assume standard `qai_hub` SDK signatures. A real job must be submitted and validated on the cloud devices.

## 3. Windows API (DPAPI & NTFS)
- [ ] **DPAPI Encryption**: The Tamper-Evident Ledger uses `CryptProtectData` via `ctypes`. This is tested on standard Windows, but ensure ARM64 Windows DPAPI behaves identically.
- [ ] **NTFS Alternate Data Streams (ADS)**: The `platform_utils.py` uses `:stream` syntax to read/write ADS for taint tracking and canonicalization validation. Verify this works correctly under the specific storage drivers of the Snapdragon hardware.

## 4. MCP Proxy & Gatekeeper
- [ ] **UI Prompts (MessageBoxW)**: `gatekeeper.py` calls `user32.MessageBoxTimeoutW` dynamically. Verify that this displays correctly on ARM64 without blocking the `asyncio` loop or encountering library path issues.
- [ ] **Performance on ARM64**: Ensure the `asyncio` proxy overhead remains completely negligible (`<1ms`) under native ARM64 Python 3.11+.
