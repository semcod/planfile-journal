# planfile-journal

Ultra-fast reverse-seek JSONL tail, memory-mapped highwater scanner, cryptographic hash chain, and PLOG/1 projection with Rust acceleration for `planfile`, compliant with `wellmanifest/data-plane`, `wellmanifest/nohardcode`, and `wellmanifest/performance`.

## Features
- **Bounded Reverse-Seek JSONL Tail (`read_jsonl_tail`)**: Walks backward via memory-mapping (`memmap2`), dynamically bounded by `PLANFILE_TAIL_MAX_BYTES` (`wellmanifest/nohardcode` & `wellmanifest/performance` `append_only_read` control).
- **Memory-Mapped Highwater Scanner (`scan_journal_highwater`)**: Scans multi-hundred-MB `operations.jsonl` files in Rust to extract per-prefix ticket ID highwaters (`{"PLF": 270, ...}`) and `[st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns]` signatures (~5.1× faster than Python line-by-line JSON parsing).
- **Cryptographic Hash Chain (`verify_journal_integrity`)**: Verifies journal integrity and event tampering in a single streaming pass.
- **PLOG/1 Serializer & Canonical Parser (`serialize_plog`, `parse_plog`)**: Bounded forensic event projection matching the Subactor/Planfile logging standard.

## Installation
```bash
pip install planfile-journal
```

## Usage
```python
from planfile_journal import (
    read_jsonl_tail,
    scan_journal_highwater,
    verify_journal_integrity,
)

# Read newest 50 events
events = read_jsonl_tail("project/journal.jsonl", limit=50)

# Extract per-prefix ticket ID highwater counters and file signature
highs, signature = scan_journal_highwater(".planfile/events/operations.jsonl")

# Verify tamper-proof cryptographic hash chain
is_valid, error, count = verify_journal_integrity("project/journal.jsonl")
assert is_valid is True
```
