use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::Value;

pub fn value_to_py(py: Python<'_>, value: &Value) -> PyResult<PyObject> {
    Ok(match value {
        Value::Null => py.None(),
        Value::Bool(flag) => flag.into_pyobject(py)?.to_owned().into_any().unbind(),
        Value::Number(number) => match (number.as_i64(), number.as_f64()) {
            (Some(whole), _) => whole.into_pyobject(py)?.into_any().unbind(),
            (None, Some(fraction)) => fraction.into_pyobject(py)?.into_any().unbind(),
            _ => py.None(),
        },
        Value::String(text) => text.into_pyobject(py)?.into_any().unbind(),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(value_to_py(py, item)?)?;
            }
            list.into_any().unbind()
        }
        Value::Object(fields) => {
            let mapping = PyDict::new(py);
            for (name, item) in fields {
                mapping.set_item(name, value_to_py(py, item)?)?;
            }
            mapping.into_any().unbind()
        }
    })
}
