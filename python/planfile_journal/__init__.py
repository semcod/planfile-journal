"""Ultra-fast reverse-seek JSONL tail, cryptographic hash chain, highwater scan, and PLOG/1 projection with Rust acceleration."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

_ID_RE = re.compile(r"^(.+)-(\d+)$")

try:
    from .planfile_journal_rs import (
        append_event_line as _rs_append_event_line,
        parse_plog as _rs_parse_plog,
        read_jsonl_tail as _rs_read_jsonl_tail,
        scan_journal_highwater as _rs_scan_journal_highwater,
        serialize_plog as _rs_serialize_plog,
        verify_journal_integrity as _rs_verify_journal_integrity,
    )
    HAS_RUST_JOURNAL = True
except ImportError:
    try:
        from planfile_journal_rs import (
            append_event_line as _rs_append_event_line,
            parse_plog as _rs_parse_plog,
            read_jsonl_tail as _rs_read_jsonl_tail,
            scan_journal_highwater as _rs_scan_journal_highwater,
            serialize_plog as _rs_serialize_plog,
            verify_journal_integrity as _rs_verify_journal_integrity,
        )
        HAS_RUST_JOURNAL = True
    except ImportError:
        HAS_RUST_JOURNAL = False
        _rs_read_jsonl_tail = None
        _rs_verify_journal_integrity = None
        _rs_append_event_line = None
        _rs_scan_journal_highwater = None
        _rs_serialize_plog = None
        _rs_parse_plog = None


def read_jsonl_tail(
    path: str | Path,
    limit: int = 50,
    max_bytes: int | None = None,
) -> list[dict[str, Any]]:
    """Return up to ``limit`` rows from the end of the JSONL file, newest first."""
    if HAS_RUST_JOURNAL and _rs_read_jsonl_tail is not None:
        return _rs_read_jsonl_tail(str(path), limit, max_bytes)

    from planfile.core.jsonl_tail import read_jsonl_tail as _py_tail
    kwargs: dict[str, Any] = {"limit": limit}
    if max_bytes is not None:
        kwargs["max_bytes"] = max_bytes
    return _py_tail(Path(path), **kwargs)


def scan_journal_highwater(path: str | Path) -> tuple[dict[str, int], list[int] | None]:
    """Scan JSONL journal via memory-mapped I/O and return (highs_dict, signature_list)."""
    if HAS_RUST_JOURNAL and _rs_scan_journal_highwater is not None:
        return _rs_scan_journal_highwater(str(path))

    p = Path(path)
    try:
        st = p.stat()
    except FileNotFoundError:
        return {}, None
    sig = [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]
    highs: dict[str, int] = {}
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                ev = row.get("event") if isinstance(row.get("event"), dict) else row
                tid = str(ev.get("ticket_id") or "")
                m = _ID_RE.fullmatch(tid)
                if m:
                    prefix, num = m.groups()
                    highs[prefix] = max(highs.get(prefix, 0), int(num))
    return highs, sig


def verify_journal_integrity(path: str | Path) -> tuple[bool, str | None, int]:
    """Verify cryptographic hash chain and line validity of a JSONL journal."""
    if HAS_RUST_JOURNAL and _rs_verify_journal_integrity is not None:
        return _rs_verify_journal_integrity(str(path))

    p = Path(path)
    if not p.exists():
        return False, f"File {path} does not exist", 0

    count = 0
    expected_prev = None
    with open(p, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                val = json.loads(line)
            except Exception as e:
                return False, f"Malformed JSON at line {idx}: {e}", count

            if isinstance(val, dict):
                event_hash = val.get("event_hash")
                if event_hash:
                    if expected_prev is not None:
                        recorded_prev = val.get("previous_hash")
                        if recorded_prev != expected_prev:
                            return (
                                False,
                                f"Hash chain broken at line {idx}: expected {expected_prev}, got {recorded_prev}",
                                count,
                            )
                    expected_prev = event_hash
                count += 1
    return True, None, count


def append_event_line(path: str | Path, line: str) -> None:
    """Atomically append a line to the journal file."""
    if HAS_RUST_JOURNAL and _rs_append_event_line is not None:
        _rs_append_event_line(str(path), line)
    else:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(line.rstrip("\r\n") + "\n")


def serialize_plog(event: dict[str, Any]) -> str:
    """Serialize event into canonical PLOG/1 line."""
    if HAS_RUST_JOURNAL and _rs_serialize_plog is not None:
        return _rs_serialize_plog(event)
    from planfile.core.forensic_log_dsl import serialize as _py_serialize
    return _py_serialize(event)


def parse_plog(line: str) -> dict[str, Any]:
    """Parse PLOG/1 line into canonical event dict."""
    if HAS_RUST_JOURNAL and _rs_parse_plog is not None:
        return _rs_parse_plog(line)
    from planfile.core.forensic_log_dsl import parse as _py_parse
    return _py_parse(line)


__all__ = [
    "HAS_RUST_JOURNAL",
    "append_event_line",
    "parse_plog",
    "read_jsonl_tail",
    "scan_journal_highwater",
    "serialize_plog",
    "verify_journal_integrity",
]
