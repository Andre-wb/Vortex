use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use serde_json::Value;

#[pyfunction]
pub fn canonical_json(py: Python<'_>, obj: Bound<'_, PyAny>) -> PyResult<Py<PyBytes>> {
    let val = _py_to_value(obj)?;
    let bytes = _serialize_sorted(&val);
    Ok(PyBytes::new(py, &bytes).into())
}

#[pyfunction]
pub fn sign_canonical(
    py: Python<'_>,
    priv_raw: &[u8],
    payload: Bound<'_, PyAny>,
) -> PyResult<String> {
    use ed25519_dalek::{Signer, SigningKey};
    if priv_raw.len() != 32 {
        return Err(PyValueError::new_err("priv_raw must be 32 bytes"));
    }
    let val = _py_to_value(payload)?;
    let bytes = _serialize_sorted(&val);
    let priv_bytes: [u8; 32] = priv_raw.try_into().unwrap();
    let sig_hex = py.allow_threads(move || {
        let sk = SigningKey::from_bytes(&priv_bytes);
        hex::encode(sk.sign(&bytes).to_bytes())
    });
    Ok(sig_hex)
}

fn _py_to_value(obj: Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(b) = obj.downcast::<PyBool>() {
        return Ok(Value::Bool(b.is_true()));
    }
    if let Ok(i) = obj.downcast::<PyInt>() {
        let v: i128 = i.extract()?;
        if v >= i64::MIN as i128 && v <= i64::MAX as i128 {
            return Ok(Value::Number(serde_json::Number::from(v as i64)));
        }
        return Ok(Value::String(v.to_string()));
    }
    if let Ok(f) = obj.downcast::<PyFloat>() {
        let v: f64 = f.extract()?;
        return Ok(serde_json::Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null));
    }
    if let Ok(s) = obj.downcast::<PyString>() {
        return Ok(Value::String(s.to_string()));
    }
    if let Ok(lst) = obj.downcast::<PyList>() {
        let mut out = Vec::with_capacity(lst.len());
        for item in lst.iter() {
            out.push(_py_to_value(item)?);
        }
        return Ok(Value::Array(out));
    }
    if let Ok(tup) = obj.downcast::<PyTuple>() {
        let mut out = Vec::with_capacity(tup.len());
        for item in tup.iter() {
            out.push(_py_to_value(item)?);
        }
        return Ok(Value::Array(out));
    }
    if let Ok(d) = obj.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (k, v) in d.iter() {
            let k_str: String = k.extract().map_err(|_| {
                PyValueError::new_err("dict keys must be strings for canonical JSON")
            })?;
            map.insert(k_str, _py_to_value(v)?);
        }
        return Ok(Value::Object(map));
    }

    Err(PyValueError::new_err(format!(
        "unsupported type for canonical JSON: {}",
        obj.get_type()
    )))
}

fn _serialize_sorted(v: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    _emit(&mut out, v);
    out
}

fn _emit(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => _emit_string(out, s),
        Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                _emit(out, item);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push(b'{');
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                _emit_string(out, k);
                out.push(b':');
                _emit(out, val);
            }
            out.push(b'}');
        }
    }
}

fn _emit_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\x08' => out.extend_from_slice(b"\\b"),
            '\x0C' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                let s = format!("\\u{:04x}", c as u32);
                out.extend_from_slice(s.as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}
