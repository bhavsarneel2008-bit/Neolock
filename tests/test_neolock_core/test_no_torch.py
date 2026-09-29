import sys
import pytest

def test_runtime_imports_without_torch():
    # Hide torch if it's installed
    sys.modules["torch"] = None
    sys.modules["transformers"] = None

    try:
        # Import core modules
        import neolock_core.cli
        import neolock_core.doctor
        import neolock_core.logging
        import neolock_core.config
        
        # Import npu_engine module
        import npu_engine.qnn_session
    except ImportError as e:
        pytest.fail(f"Runtime packages failed to import when ML tooling is missing: {e}")
    finally:
        # Restore just in case
        sys.modules.pop("torch", None)
        sys.modules.pop("transformers", None)
