use ahash::AHashMap;
use memmap2::Mmap;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[allow(dead_code)]
pub fn compute_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

/// Return `[st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns]` matching `JournalHighwater.signature()`.
pub fn file_signature(path: &Path) -> Option<[u64; 5]> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime_ns = (meta.mtime() as i128 * 1_000_000_000 + meta.mtime_nsec() as i128).max(0) as u64;
    let ctime_ns = (meta.ctime() as i128 * 1_000_000_000 + meta.ctime_nsec() as i128).max(0) as u64;
    Some([meta.dev(), meta.ino(), meta.len(), mtime_ns, ctime_ns])
}

fn parse_prefix_number(ticket_id: &str) -> Option<(&str, u64)> {
    let idx = ticket_id.rfind('-')?;
    if idx == 0 || idx + 1 >= ticket_id.len() {
        return None;
    }
    let prefix = &ticket_id[..idx];
    let num_str = &ticket_id[idx + 1..];
    if !num_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let number = num_str.parse::<u64>().ok()?;
    Some((prefix, number))
}

/// Memory-mapped scan of `operations.jsonl` to extract per-prefix ticket ID highwater counters.
/// Avoids allocating Python strings/dicts for every line in multi-hundred-MB journals.
pub fn scan_journal_highwater(path: &Path) -> Result<(AHashMap<String, u64>, Option<[u64; 5]>), String> {
    let mut highs: AHashMap<String, u64> = AHashMap::new();
    let Some(sig_before) = file_signature(path) else {
        return Ok((highs, None));
    };
    let file = File::open(path).map_err(|e| e.to_string())?;
    let file_len = sig_before[2] as usize;
    if file_len == 0 {
        return Ok((highs, Some(sig_before)));
    }
    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| e.to_string())?;
    for raw_line in mmap.split(|&b| b == b'\n') {
        let line = raw_line
            .strip_prefix(b"\r")
            .unwrap_or(raw_line)
            .strip_suffix(b"\r")
            .unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_slice::<Value>(line) {
            if let Some(tid) = val
                .get("event")
                .and_then(|e| e.get("ticket_id"))
                .or_else(|| val.get("ticket_id"))
                .and_then(|v| v.as_str())
            {
                if let Some((prefix, num)) = parse_prefix_number(tid) {
                    let entry = highs.entry(prefix.to_string()).or_insert(0);
                    if num > *entry {
                        *entry = num;
                    }
                }
            }
        }
    }
    let sig_after = file_signature(path);
    if sig_after != Some(sig_before) {
        return Err("allocator journal changed during locked scan".to_string());
    }
    Ok((highs, sig_after))
}

/// Verifies that the append-only journal has a valid format and unbroken hash chain.
/// Returns (is_valid, error_message, event_count).
pub fn verify_journal_integrity(path: &Path) -> (bool, Option<String>, usize) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return (false, Some(format!("Cannot open file: {}", e)), 0),
    };

    let reader = BufReader::new(file);
    let mut count = 0;
    let mut expected_prev_hash: Option<String> = None;

    for (line_num, line_res) in reader.lines().enumerate() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => return (false, Some(format!("IO error at line {}: {}", line_num + 1, e)), count),
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let val: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => return (false, Some(format!("Malformed JSON at line {}: {}", line_num + 1, e)), count),
        };

        if let Some(obj) = val.as_object() {
            if let Some(event_hash) = obj.get("event_hash").and_then(|h| h.as_str()) {
                if let Some(prev) = &expected_prev_hash {
                    if let Some(recorded_prev) = obj.get("previous_hash").and_then(|h| h.as_str()) {
                        if recorded_prev != prev {
                            return (
                                false,
                                Some(format!(
                                    "Hash chain broken at line {}: expected previous_hash '{}', got '{}'",
                                    line_num + 1,
                                    prev,
                                    recorded_prev
                                )),
                                count,
                            );
                        }
                    }
                }
                expected_prev_hash = Some(event_hash.to_string());
            }
            count += 1;
        }
    }

    (true, None, count)
}

/// Appends a single JSON event line to the journal atomically with fsync.
pub fn append_event_line(path: &Path, line: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    writeln!(file, "{}", line.trim_end())?;
    file.sync_data()?;
    Ok(())
}
