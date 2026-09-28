"""Comprehensive test suite for planfile-journal."""

import hashlib
import json
import pytest
from planfile_journal import (
    read_jsonl_tail,
    verify_journal_integrity,
    append_event_line,
    serialize_plog,
    parse_plog,
    HAS_RUST_JOURNAL,
)


def test_read_jsonl_tail(tmp_path):
    journal_file = tmp_path / "events.jsonl"
    with open(journal_file, "w", encoding="utf-8") as f:
        for i in range(100):
            f.write(json.dumps({"event_id": f"evt-{i:03d}", "value": i}) + "\n")

    # Read last 5 events
    rows = read_jsonl_tail(journal_file, limit=5)
    assert len(rows) == 5
    # Newest first: evt-099, evt-098, evt-097, evt-096, evt-095
    assert rows[0]["event_id"] == "evt-099"
    assert rows[0]["value"] == 99
    assert rows[4]["event_id"] == "evt-095"


def test_read_jsonl_tail_empty_and_missing(tmp_path):
    missing_file = tmp_path / "nonexistent.jsonl"
    assert read_jsonl_tail(missing_file, limit=10) == []

    empty_file = tmp_path / "empty.jsonl"
    empty_file.touch()
    assert read_jsonl_tail(empty_file, limit=10) == []


def test_verify_journal_integrity(tmp_path):
    journal_file = tmp_path / "audit.jsonl"

    prev_hash = None
    with open(journal_file, "w", encoding="utf-8") as f:
        for i in range(50):
            data_str = f"payload-{i}"
            curr_hash = hashlib.sha256(f"{prev_hash or ''}:{data_str}".encode()).hexdigest()
            row = {
                "event_id": f"E-{i}",
                "event_hash": curr_hash,
                "data": data_str,
            }
            if prev_hash:
                row["previous_hash"] = prev_hash
            prev_hash = curr_hash
            f.write(json.dumps(row) + "\n")

    is_valid, err, count = verify_journal_integrity(journal_file)
    assert is_valid is True
    assert err is None
    assert count == 50

    # Tamper with line 25
    lines = journal_file.read_text().splitlines()
    tampered_row = json.loads(lines[25])
    tampered_row["previous_hash"] = "tampered_fake_hash_12345"
    lines[25] = json.dumps(tampered_row)
    journal_file.write_text("\n".join(lines) + "\n")

    is_valid_bad, err_bad, _ = verify_journal_integrity(journal_file)
    assert is_valid_bad is False
    assert "Hash chain broken" in err_bad


def test_append_event_line(tmp_path):
    journal_file = tmp_path / "append.jsonl"
    append_event_line(journal_file, json.dumps({"action": "create", "id": 1}))
    append_event_line(journal_file, json.dumps({"action": "update", "id": 2}))

    rows = read_jsonl_tail(journal_file, limit=10)
    assert len(rows) == 2
    assert rows[0]["action"] == "update"
    assert rows[1]["action"] == "create"


def test_plog_roundtrip():
    event = {
        "timestamp": "2026-09-28T12:00:00Z",
        "event_id": "EVT-100",
        "event_hash": "abc123hash",
        "oql": "apply",
        "kind": "ticket",
        "ticket_id": "T-01",
        "actor": "agent-1",
        "source": "planfile",
        "mode": "apply",
        "status": "in_progress",
        "correlation_id": "corr-1",
        "causation_id": "caus-1",
        "receipt_ref": "rcpt-1",
        "replayable": True,
        "data": {
            "name": "Implement feature",
            "priority": "high",
        },
    }

    line = serialize_plog(event)
    assert line.startswith("PLOG/1\t")
    assert "ticket_id=\"T-01\"" in line

    parsed = parse_plog(line)
    assert parsed["schema"] == "planfile.forensic-log/v1"
    assert parsed["event_id"] == "EVT-100"
    assert parsed["ticket_id"] == "T-01"
    assert parsed["logic"]["name"] == "Implement feature"
    assert parsed["logic"]["priority"] == "high"


def test_plog_invalid_prefix():
    with pytest.raises(Exception):
        parse_plog("INVALID/1\ttimestamp=\"2026-01-01\"")
