use std::path::Path;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

mod hash_chain;
mod plog;
mod tail;

use hash_chain::{append_event_line as rs_append_event_line, verify_journal_integrity as rs_verify_journal_integrity};
use plog::{parse_plog as rs_parse_plog, serialize_plog as rs_serialize_plog};
use tail::{read_jsonl_tail as rs_read_jsonl_tail, OPERATIONS_TAIL_MAX_BYTES};

fn json_to_py<'py>(py: Python<'py>, val: &serde_json::Value) -> PyResult<PyObject> {
    match val {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok(b.into_py(py)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_py(py))
            } else {
                Ok(n.to_string().into_py(py))
            }
        }
        serde_json::Value::String(s) => Ok(s.into_py(py)),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty_bound(py);
            for item in arr {
                list.append(json_to_py(py, item)?)?;
            }
            Ok(list.into_py(py))
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in map {
                dict.set_item(k, json_to_py(py, v)?)?;
            }
            Ok(dict.into_py(py))
        }
    }
}

#[pyfunction]
#[pyo3(signature = (path, limit=50, max_bytes=None))]
fn read_jsonl_tail<'py>(
    py: Python<'py>,
    path: &str,
    limit: usize,
    max_bytes: Option<usize>,
) -> PyResult<PyObject> {
    let budget = max_bytes.unwrap_or(OPERATIONS_TAIL_MAX_BYTES);
    let rows = rs_read_jsonl_tail(Path::new(path), limit, budget);

    let py_list = PyList::empty_bound(py);
    for row in rows {
        py_list.append(json_to_py(py, &row)?)?;
    }

    Ok(py_list.into_py(py))
}

#[pyfunction]
fn verify_journal_integrity(path: &str) -> (bool, Option<String>, usize) {
    rs_verify_journal_integrity(Path::new(path))
}

#[pyfunction]
fn append_event_line(path: &str, line: &str) -> PyResult<()> {
    rs_append_event_line(Path::new(path), line).map_err(|e| {
        PyValueError::new_err(format!("Failed to append event line: {}", e))
    })
}

#[pyfunction]
fn serialize_plog<'py>(py: Python<'py>, event: &Bound<'py, PyDict>) -> PyResult<String> {
    let json_module = py.import_bound("json")?;
    let json_str: String = json_module.call_method1("dumps", (event,))?.extract()?;
    let val: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| PyValueError::new_err(format!("Invalid event JSON: {}", e)))?;

    if let Some(map) = val.as_object() {
        Ok(rs_serialize_plog(map))
    } else {
        Err(PyValueError::new_err("Event must be a dict"))
    }
}

#[pyfunction]
fn parse_plog<'py>(py: Python<'py>, line: &str) -> PyResult<PyObject> {
    match rs_parse_plog(line) {
        Ok(map) => json_to_py(py, &serde_json::Value::Object(map)),
        Err(err) => Err(PyValueError::new_err(err)),
    }
}

#[pymodule]
fn planfile_journal_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(read_jsonl_tail, m)?)?;
    m.add_function(wrap_pyfunction!(verify_journal_integrity, m)?)?;
    m.add_function(wrap_pyfunction!(append_event_line, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_plog, m)?)?;
    m.add_function(wrap_pyfunction!(parse_plog, m)?)?;
    Ok(())
}
