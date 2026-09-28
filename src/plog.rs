use serde_json::{Map, Value};

pub const PREFIX: &str = "PLOG/1";
pub const SCHEMA: &str = "planfile.forensic-log/v1";

pub const LOGIC_KEYS: &[&str] = &[
    "name",
    "priority",
    "reason",
    "decision",
    "action",
    "changes",
    "previous_status",
    "status",
    "previous_execution_state",
    "execution_state",
    "outcome",
    "error",
    "message",
    "level",
    "queue",
    "collection",
    "idempotency_key",
];

pub const FIELDS: &[&str] = &[
    "timestamp",
    "event_id",
    "event_hash",
    "type",
    "kind",
    "ticket_id",
    "actor",
    "source",
    "mode",
    "status",
    "correlation_id",
    "causation_id",
    "receipt_ref",
    "replayable",
    "logic",
];

fn bounded_value(val: &Value) -> Value {
    match val {
        Value::String(s) => {
            if s.len() > 2000 {
                Value::String(s.chars().take(2000).collect())
            } else {
                val.clone()
            }
        }
        Value::Array(arr) => {
            let bounded: Vec<Value> = arr.iter().take(30).map(bounded_value).collect();
            Value::Array(bounded)
        }
        Value::Object(map) => {
            let mut bounded = Map::new();
            for (k, v) in map.iter().take(30) {
                bounded.insert(k.clone(), bounded_value(v));
            }
            Value::Object(bounded)
        }
        _ => val.clone(),
    }
}

fn extract_logic(event: &Map<String, Value>) -> Value {
    let empty_map = Map::new();
    let data = event
        .get("data")
        .and_then(|d| d.as_object())
        .unwrap_or(&empty_map);
    let payload = data
        .get("payload")
        .and_then(|p| p.as_object())
        .unwrap_or(data);

    let mut logic = Map::new();
    for &key in LOGIC_KEYS {
        if let Some(val) = payload.get(key) {
            let is_empty = match val {
                Value::Null => true,
                Value::String(s) => s.is_empty(),
                Value::Array(a) => a.is_empty(),
                Value::Object(o) => o.is_empty(),
                _ => false,
            };
            if !is_empty {
                logic.insert(key.to_string(), bounded_value(val));
            }
        }
    }

    if !logic.contains_key("status") {
        if let Some(st) = event.get("status").and_then(|s| s.as_str()) {
            if !st.is_empty() && st != "recorded" {
                logic.insert("status".to_string(), Value::String(st.to_string()));
            }
        }
    }

    Value::Object(logic)
}

pub fn project_event(event: &Map<String, Value>) -> Map<String, Value> {
    let mut rec = Map::new();
    rec.insert("schema".to_string(), Value::String(SCHEMA.to_string()));

    let get_str = |key: &str, default: &str| -> Value {
        Value::String(
            event
                .get(key)
                .and_then(|v| v.as_str())
                .unwrap_or(default)
                .to_string(),
        )
    };

    rec.insert("timestamp".to_string(), get_str("timestamp", "-"));
    rec.insert("event_id".to_string(), get_str("event_id", "-"));
    rec.insert("event_hash".to_string(), get_str("event_hash", "-"));
    rec.insert(
        "type".to_string(),
        Value::String(
            event
                .get("oql")
                .and_then(|v| v.as_str())
                .unwrap_or("observe")
                .to_string(),
        ),
    );
    rec.insert("kind".to_string(), get_str("kind", "operation"));
    rec.insert("ticket_id".to_string(), get_str("ticket_id", "-"));
    rec.insert("actor".to_string(), get_str("actor", "system"));
    rec.insert("source".to_string(), get_str("source", "planfile"));
    rec.insert("mode".to_string(), get_str("mode", "observe"));
    rec.insert("status".to_string(), get_str("status", "recorded"));
    rec.insert(
        "correlation_id".to_string(),
        get_str("correlation_id", "-"),
    );
    rec.insert("causation_id".to_string(), get_str("causation_id", "-"));
    rec.insert("receipt_ref".to_string(), get_str("receipt_ref", "-"));
    rec.insert(
        "replayable".to_string(),
        Value::Bool(
            event
                .get("replayable")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
        ),
    );
    rec.insert("logic".to_string(), extract_logic(event));

    rec
}

pub fn serialize_plog(event_map: &Map<String, Value>) -> String {
    let projected = project_event(event_map);
    let mut parts = Vec::with_capacity(FIELDS.len() + 1);
    parts.push(PREFIX.to_string());

    for &field in FIELDS {
        let val = projected.get(field).unwrap_or(&Value::Null);
        let encoded = serde_json::to_string(val).unwrap_or_else(|_| "null".to_string());
        parts.push(format!("{}={}", field, encoded));
    }

    parts.join("\t")
}

pub fn parse_plog(line: &str) -> Result<Map<String, Value>, String> {
    let raw = line.trim_end_matches(['\r', '\n']);
    let prefix_tab = format!("{}\t", PREFIX);
    if !raw.starts_with(&prefix_tab) {
        return Err("plog_prefix_invalid".to_string());
    }

    let tokens: Vec<&str> = raw.split('\t').collect();
    let mut values = Map::new();
    values.insert("schema".to_string(), Value::String(SCHEMA.to_string()));

    for &token in &tokens[1..] {
        let eq_pos = token.find('=').ok_or("plog_field_invalid")?;
        let key = &token[..eq_pos];
        let encoded = &token[eq_pos + 1..];

        let val: Value = serde_json::from_str(encoded)
            .map_err(|_| format!("plog_value_invalid:{}", key))?;
        values.insert(key.to_string(), val);
    }

    for &field in FIELDS {
        if !values.contains_key(field) {
            return Err(format!("plog_field_required:{}", field));
        }
    }

    // Verify canonical representation
    let mut canonical_parts = Vec::with_capacity(FIELDS.len() + 1);
    canonical_parts.push(PREFIX.to_string());
    for &field in FIELDS {
        let val = &values[field];
        let encoded = serde_json::to_string(val).unwrap_or_default();
        canonical_parts.push(format!("{}={}", field, encoded));
    }
    let canonical = canonical_parts.join("\t");
    if canonical != raw {
        return Err("plog_line_not_canonical".to_string());
    }

    Ok(values)
}
