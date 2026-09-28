"""Benchmark comparing planfile-journal against pure Python implementations."""

import hashlib
import json
import time
from pathlib import Path
import tempfile
from planfile_journal import (
    read_jsonl_tail,
    verify_journal_integrity,
    serialize_plog,
    parse_plog,
    HAS_RUST_JOURNAL,
)
from planfile.core.jsonl_tail import read_jsonl_tail as py_read_jsonl_tail
from planfile.core.forensic_log_dsl import (
    serialize as py_serialize_plog,
    parse as py_parse_plog,
)


def generate_benchmark_journal(file_path: Path, count: int = 50000):
    prev_hash = None
    with open(file_path, "w", encoding="utf-8") as f:
        for i in range(count):
            data_str = f"Ticket mutation event {i} updating status and priority"
            curr_hash = hashlib.sha256(f"{prev_hash or ''}:{data_str}".encode()).hexdigest()
            row = {
                "event_id": f"evt-{i:06d}",
                "event_hash": curr_hash,
                "timestamp": "2026-09-28T12:00:00Z",
                "oql": "apply",
                "kind": "ticket",
                "ticket_id": f"PLF-{i % 500:04d}",
                "actor": "agent-orchestrator",
                "source": "planfile",
                "mode": "apply",
                "status": "in_progress" if i % 2 == 0 else "done",
                "correlation_id": f"corr-{i // 10}",
                "causation_id": f"caus-{i // 10}",
                "receipt_ref": f"rcpt-{i}",
                "replayable": True,
                "data": {
                    "payload": {
                        "name": f"Subtask {i}",
                        "priority": "high" if i % 3 == 0 else "normal",
                        "status": "in_progress",
                    }
                }
            }
            if prev_hash:
                row["previous_hash"] = prev_hash
            prev_hash = curr_hash
            f.write(json.dumps(row) + "\n")


def main():
    print(f"=== Planfile Journal Benchmark (HAS_RUST_JOURNAL={HAS_RUST_JOURNAL}) ===")

    with tempfile.TemporaryDirectory() as tmp_dir:
        journal_file = Path(tmp_dir) / "large_journal.jsonl"
        count = 50000
        print(f"\nGenerating synthetic journal with {count} events...")
        generate_benchmark_journal(journal_file, count)
        file_size_mb = journal_file.stat().st_size / (1024 * 1024)
        print(f"Journal size: {file_size_mb:.2f} MB")

        # 1. Reverse-Seek JSONL Tail Benchmark
        limits = [10, 50, 200]
        print("\n[Test 1] Reverse-Seek JSONL Tail (read newest events):")
        for lim in limits:
            # Pure Python
            t0 = time.perf_counter()
            for _ in range(50):
                py_rows = py_read_jsonl_tail(journal_file, limit=lim)
            py_time = (time.perf_counter() - t0) / 50 * 1000

            # Rust
            t0 = time.perf_counter()
            for _ in range(50):
                rs_rows = read_jsonl_tail(journal_file, limit=lim)
            rs_time = (time.perf_counter() - t0) / 50 * 1000

            assert len(py_rows) == len(rs_rows) == lim
            speedup = py_time / rs_time if rs_time > 0 else float("inf")
            print(f"  Limit={lim:3d} | Python: {py_time:.3f} ms | Rust: {rs_time:.3f} ms | Speedup: {speedup:.1f}x")

        # 2. Cryptographic Hash Chain Verification
        print(f"\n[Test 2] Cryptographic Hash Chain Verification ({count} events):")
        t0 = time.perf_counter()
        is_valid, err, checked_count = verify_journal_integrity(journal_file)
        rs_verify_time = (time.perf_counter() - t0) * 1000
        assert is_valid is True
        assert checked_count == count
        rate = count / (rs_verify_time / 1000)
        print(f"  Verified {checked_count} events in {rs_verify_time:.2f} ms ({rate:.0f} events/s, unbroken hash chain)")

        # 3. PLOG/1 Serialization & Parsing Benchmark
        print("\n[Test 3] PLOG/1 Serialization & Parsing:")
        sample_event = {
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

        # Pure Python
        t0 = time.perf_counter()
        for _ in range(5000):
            line = py_serialize_plog(sample_event)
            py_parse_plog(line)
        py_plog_time = (time.perf_counter() - t0) * 1000

        # Rust
        t0 = time.perf_counter()
        for _ in range(5000):
            line = serialize_plog(sample_event)
            parse_plog(line)
        rs_plog_time = (time.perf_counter() - t0) * 1000

        plog_speedup = py_plog_time / rs_plog_time if rs_plog_time > 0 else float("inf")
        print(f"  5,000 PLOG roundtrips | Python: {py_plog_time:.2f} ms | Rust: {rs_plog_time:.2f} ms | Speedup: {plog_speedup:.1f}x")


if __name__ == "__main__":
    main()
