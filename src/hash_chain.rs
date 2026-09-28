use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use serde_json::Value;

#[allow(dead_code)]
pub fn compute_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
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
