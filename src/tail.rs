use memmap2::Mmap;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::path::Path;

pub const OPERATIONS_TAIL_MAX_BYTES: usize = 256 * 1024 * 1024;
#[allow(dead_code)]
pub const CHUNK_BYTES: usize = 1024 * 1024;

/// Dynamic tail byte budget governed by `wellmanifest/nohardcode` (`PLANFILE_TAIL_MAX_BYTES`).
pub fn default_tail_max_bytes() -> usize {
    env::var("PLANFILE_TAIL_MAX_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(4_096, 1_073_741_824))
        .unwrap_or(OPERATIONS_TAIL_MAX_BYTES)
}

/// Reverse-seek reading of JSONL file up to `limit` rows or `max_bytes` scanned.
/// Returns rows newest-first.
pub fn read_jsonl_tail(
    path: &Path,
    limit: usize,
    max_bytes: usize,
) -> Vec<Value> {
    if limit == 0 {
        return Vec::new();
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let metadata = match file.metadata() {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };

    let file_len = metadata.len() as usize;
    if file_len == 0 {
        return Vec::new();
    }

    let mmap = match unsafe { Mmap::map(&file) } {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };

    let budget = max_bytes.min(file_len);
    let start_pos = file_len.saturating_sub(budget);
    let slice = &mmap[start_pos..file_len];

    let mut rows = Vec::with_capacity(limit.min(1000));
    let mut end = slice.len();

    while end > 0 && rows.len() < limit {
        let prev_nl = slice[..end].iter().rposition(|&b| b == b'\n');
        let line_start = match prev_nl {
            Some(pos) => pos + 1,
            None => 0,
        };

        let raw_line = &slice[line_start..end];
        let trimmed = raw_line.strip_prefix(b"\r").unwrap_or(raw_line);
        let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);

        if !trimmed.is_empty() {
            if let Ok(val) = serde_json::from_slice::<Value>(trimmed) {
                if val.is_object() {
                    rows.push(val);
                }
            }
        }

        if line_start == 0 {
            break;
        }
        end = line_start - 1;
    }

    rows
}
