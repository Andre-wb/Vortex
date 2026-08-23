use crate::wire::payload::Decoded;
use crate::wire::pubkey::normalize_pubkey;
use crate::wire::NAME_MAX_CHARS;
use serde_json::Value;

pub fn decode(data: &[u8], fallback_name: &str, fallback_port: u16) -> Option<Decoded> {
    let value: Value = serde_json::from_slice(data).ok()?;
    let object = value.as_object()?;

    let name = read_name(object.get("name"), fallback_name);
    let port = read_port(object.get("port"), fallback_port)?;
    let pubkey = normalize_pubkey(object.get("pubkey").and_then(Value::as_str));

    Some(Decoded { name, port, pubkey })
}

fn read_name(field: Option<&Value>, fallback: &str) -> String {
    let raw = match field {
        Some(Value::String(text)) => text.as_str(),
        _ => fallback,
    };
    raw.chars().take(NAME_MAX_CHARS).collect()
}

fn read_port(field: Option<&Value>, fallback: u16) -> Option<u16> {
    let candidate = match field {
        None => return Some(fallback),
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|x| x as i64))?,
        Some(Value::String(text)) => text.trim().parse::<i64>().ok()?,
        Some(_) => return None,
    };
    if (1..=65535).contains(&candidate) {
        Some(candidate as u16)
    } else {
        None
    }
}
