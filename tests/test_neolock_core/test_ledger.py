import pytest
import os
import struct
import json
from pathlib import Path
import neolock_core.ledger as ledger
from neolock_core.platform_utils import unprotect_data, protect_data

@pytest.fixture(autouse=True)
def isolated_ledger(tmp_path, monkeypatch):
    test_ledger = tmp_path / "ledger.enc"
    monkeypatch.setattr(ledger, "LEDGER_FILE", test_ledger)
    yield test_ledger

def test_ledger_append_and_verify():
    # Empty verify
    ok, msg = ledger.verify_ledger()
    assert ok is True
    
    # Append
    ledger.append_to_ledger("ALLOW", "", "", "read_file", {"path": "test.txt"})
    ok, msg = ledger.verify_ledger()
    assert ok is True
    assert "1 entries" in msg
    
    # Append second
    ledger.append_to_ledger("BLOCK", "P1", "Traversals", "read_file", {"path": "../test.txt"})
    ok, msg = ledger.verify_ledger()
    assert ok is True
    assert "2 entries" in msg

def test_ledger_tampering_corrupt_length():
    ledger.append_to_ledger("ALLOW", "", "", "test", {})
    
    with open(ledger.LEDGER_FILE, "ab") as f:
        f.write(b'\x01') # Incomplete length
        
    ok, msg = ledger.verify_ledger()
    assert ok is False
    assert "incomplete length header" in msg

def test_ledger_tampering_data_modification():
    ledger.append_to_ledger("ALLOW", "", "", "test", {})
    ledger.append_to_ledger("BLOCK", "", "", "test", {})
    
    # We will manually read, decrypt, modify, re-encrypt the first entry
    blobs = []
    with open(ledger.LEDGER_FILE, "rb") as f:
        while True:
            lbytes = f.read(4)
            if not lbytes: break
            length = struct.unpack("<I", lbytes)[0]
            blobs.append(f.read(length))
            
    # Modify the first blob
    json_data = unprotect_data(blobs[0])
    entry_dict = json.loads(json_data.decode('utf-8'))
    entry_dict["decision"] = "ASK" # Tamper!
    
    tampered_json = json.dumps(entry_dict).encode('utf-8')
    tampered_blob = protect_data(tampered_json)
    
    # Write back
    with open(ledger.LEDGER_FILE, "wb") as f:
        f.write(struct.pack("<I", len(tampered_blob)))
        f.write(tampered_blob)
        f.write(struct.pack("<I", len(blobs[1])))
        f.write(blobs[1])
        
    ok, msg = ledger.verify_ledger()
    assert ok is False
    assert "entry_hash mismatch" in msg

def test_ledger_tampering_chain_break():
    ledger.append_to_ledger("ALLOW", "", "", "test1", {})
    ledger.append_to_ledger("ALLOW", "", "", "test2", {})
    ledger.append_to_ledger("ALLOW", "", "", "test3", {})
    
    # Delete the middle entry
    blobs = []
    with open(ledger.LEDGER_FILE, "rb") as f:
        while True:
            lbytes = f.read(4)
            if not lbytes: break
            length = struct.unpack("<I", lbytes)[0]
            blobs.append(f.read(length))
            
    # Write back without middle
    with open(ledger.LEDGER_FILE, "wb") as f:
        f.write(struct.pack("<I", len(blobs[0])))
        f.write(blobs[0])
        f.write(struct.pack("<I", len(blobs[2])))
        f.write(blobs[2])
        
    ok, msg = ledger.verify_ledger()
    assert ok is False
    assert "prev_hash mismatch" in msg
