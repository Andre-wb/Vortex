//! Приведение значений JSON к строке так же, как это делал `str()` в Python.
//!
//! Правила движка исторически сопоставлялись со строковым представлением
//! значений, поэтому `true` должно давать `True`, а `null` — `None`.

use serde_json::Value;

pub fn python_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::String(s) => s.clone(),
        Value::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() => format_float(f),
            _ => n.to_string(),
        },
        other => other.to_string(),
    }
}

fn format_float(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 {
        format!("{value:.1}")
    } else {
        format!("{value}")
    }
}

#[cfg(test)]
mod tests {
    use super::python_str;
    use serde_json::json;

    #[test]
    fn matches_python_scalar_repr() {
        assert_eq!(python_str(&json!(null)), "None");
        assert_eq!(python_str(&json!(true)), "True");
        assert_eq!(python_str(&json!(false)), "False");
        assert_eq!(python_str(&json!(42)), "42");
        assert_eq!(python_str(&json!(1.0)), "1.0");
        assert_eq!(python_str(&json!(1.5)), "1.5");
        assert_eq!(python_str(&json!("текст")), "текст");
    }
}
