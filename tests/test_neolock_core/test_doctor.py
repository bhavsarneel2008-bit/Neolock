import pytest
from neolock_core.doctor import run_doctor

def test_run_doctor_does_not_crash(capsys):
    result = run_doctor()
    captured = capsys.readouterr()
    assert "=== Neolock System Doctor ===" in captured.out
    assert "OS/Arch:" in captured.out
    assert "Python Architecture:" in captured.out
    assert "ONNX Runtime Version:" in captured.out or "ONNX Runtime Check:" in captured.out
    assert "Available ORT Providers:" in captured.out or "ONNX Runtime Check:" in captured.out
    assert "QnnHtp.dll Check:" in captured.out
    assert "Context-binary Cache" in captured.out
    assert "=== Doctor Report ===" in captured.out
    assert isinstance(result, bool)
