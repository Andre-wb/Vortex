//! Обход JSON-документа в плоский список полей.
//!
//! Пути строятся как `outer.inner[0]`. Для объектов проверяется и сам ключ —
//! он может нести полезную нагрузку не хуже значения.

use crate::domain::body_field::BodyField;
use crate::util::python_repr::python_str;
use serde_json::Value;

pub fn flatten(value: &Value) -> Vec<BodyField> {
    let mut fields = Vec::new();
    walk(value, "", &mut fields);
    fields
}

fn walk(value: &Value, path: &str, out: &mut Vec<BodyField>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let current = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                // Сам ключ — тоже подозреваемый.
                out.push(BodyField::new(current.clone(), key.clone()));
                if child.is_object() || child.is_array() {
                    walk(child, &current, out);
                } else {
                    out.push(BodyField::new(current, python_str(child)));
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let current = format!("{path}[{index}]");
                if item.is_object() || item.is_array() {
                    walk(item, &current, out);
                } else {
                    out.push(BodyField::new(current, python_str(item)));
                }
            }
        }
        // Скаляр на верхнем уровне полем не считается — так же вёл себя прежний движок.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::flatten;
    use serde_json::json;

    #[test]
    fn builds_dotted_and_indexed_paths() {
        let fields = flatten(&json!({"user": {"name": "Аня"}, "tags": ["a", "b"]}));
        let pairs: Vec<(&str, &str)> = fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert!(pairs.contains(&("user", "user")));
        assert!(pairs.contains(&("user.name", "name")));
        assert!(pairs.contains(&("user.name", "Аня")));
        assert!(pairs.contains(&("tags[0]", "a")));
        assert!(pairs.contains(&("tags[1]", "b")));
    }

    #[test]
    fn scalars_use_python_style_repr() {
        let fields = flatten(&json!({"ok": true, "missing": null}));
        let values: Vec<&str> = fields.iter().map(|f| f.value.as_str()).collect();
        assert!(values.contains(&"True"));
        assert!(values.contains(&"None"));
    }

    #[test]
    fn top_level_scalar_yields_nothing() {
        assert!(flatten(&json!("просто строка")).is_empty());
    }
}
