# planfile-journal

Ultra-fast reverse-seek JSONL tail, cryptographic hash chain, and PLOG/1 projection with Rust acceleration for `planfile`.

## Features
- **Bounded Reverse-Seek JSONL Tail**: Walks backward in chunks or via memory-mapping without reading the entire historical journal into memory.
- **Microsecond Response**: Reads the newest records from a 500 MB journal in under 1 ms.
- **Cryptographic Hash Chain (SHA-256)**: Verifies journal integrity and event tampering in a single streaming pass.
- **PLOG/1 Serializer & Canonical Parser**: Bounded forensic event projection matching the Subactor/Planfile logging standard.

## Installation
```bash
pip install planfile-journal
```

## Usage
```python
from planfile_journal import read_jsonl_tail, verify_journal_integrity

# Read newest 50 events matching a filter
events = read_jsonl_tail("project/journal.jsonl", limit=50)

# Verify tamper-proof cryptographic hash chain
is_valid, error = verify_journal_integrity("project/journal.jsonl")
assert is_valid is True
```
