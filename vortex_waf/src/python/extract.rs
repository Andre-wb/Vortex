//! Разбор Python-словарей в примитивные описания крейта.

use crate::interop::config_spec::ConfigSpec;
use crate::interop::request_spec::RequestSpec;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

/// Значение по ключу, если оно есть и не `None`.
fn item<'py>(dict: &Bound<'py, PyDict>, key: &str) -> Option<Bound<'py, PyAny>> {
    match dict.get_item(key) {
        Ok(Some(value)) if !value.is_none() => Some(value),
        _ => None,
    }
}

fn string_item(dict: &Bound<'_, PyDict>, key: &str) -> Option<String> {
    item(dict, key).and_then(|value| value.extract::<String>().ok())
}

fn usize_item(dict: &Bound<'_, PyDict>, key: &str) -> Option<usize> {
    item(dict, key).and_then(|value| value.extract::<usize>().ok())
}

fn u64_item(dict: &Bound<'_, PyDict>, key: &str) -> Option<u64> {
    item(dict, key).and_then(|value| value.extract::<u64>().ok())
}

/// Список строк из любой последовательности (list, tuple, set).
fn string_list_item(dict: &Bound<'_, PyDict>, key: &str) -> Option<Vec<String>> {
    let value = item(dict, key)?;
    if let Ok(list) = value.extract::<Vec<String>>() {
        return Some(list);
    }
    let mut collected = Vec::new();
    for entry in value.try_iter().ok()? {
        if let Ok(text) = entry.ok()?.extract::<String>() {
            collected.push(text);
        }
    }
    Some(collected)
}

/// Пары «ключ — значение» из словаря; значения приводятся к строке.
fn pairs_item(dict: &Bound<'_, PyDict>, key: &str) -> Vec<(String, String)> {
    let Some(value) = item(dict, key) else {
        return Vec::new();
    };
    let Ok(mapping) = value.downcast_into::<PyDict>() else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    for (raw_key, raw_value) in mapping.iter() {
        let Ok(name) = raw_key.extract::<String>() else {
            continue;
        };
        pairs.push((name, to_text(&raw_value)));
    }
    pairs
}

/// Пары параметров: значение может быть списком — тогда пара повторяется.
fn params_item(dict: &Bound<'_, PyDict>, key: &str) -> Vec<(String, String)> {
    let Some(value) = item(dict, key) else {
        return Vec::new();
    };
    let Ok(mapping) = value.downcast_into::<PyDict>() else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    for (raw_key, raw_value) in mapping.iter() {
        let Ok(name) = raw_key.extract::<String>() else {
            continue;
        };
        if let Ok(list) = raw_value.downcast::<PyList>() {
            for entry in list.iter() {
                pairs.push((name.clone(), to_text(&entry)));
            }
        } else {
            pairs.push((name, to_text(&raw_value)));
        }
    }
    pairs
}

/// Строковое представление значения: строки берутся как есть, остальное — через
/// `str()`, как это делал прежний движок.
fn to_text(value: &Bound<'_, PyAny>) -> String {
    if let Ok(text) = value.downcast::<PyString>() {
        return text.to_string_lossy().into_owned();
    }
    value
        .str()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn request_spec(dict: &Bound<'_, PyDict>) -> RequestSpec {
    RequestSpec {
        client_ip: string_item(dict, "client_ip"),
        method: string_item(dict, "method"),
        path: string_item(dict, "path"),
        url: string_item(dict, "url"),
        headers: pairs_item(dict, "headers"),
        params: params_item(dict, "params"),
        content_type: string_item(dict, "content_type"),
        body: string_item(dict, "body"),
    }
}

pub fn config_spec(dict: Option<&Bound<'_, PyDict>>) -> ConfigSpec {
    let Some(dict) = dict else {
        return ConfigSpec::default();
    };
    ConfigSpec {
        rate_limit_requests: usize_item(dict, "rate_limit_requests"),
        rate_limit_window: u64_item(dict, "rate_limit_window"),
        block_duration: u64_item(dict, "block_duration"),
        max_content_length: usize_item(dict, "max_content_length"),
        safe_params: string_list_item(dict, "safe_params"),
        whitelist_ips: string_list_item(dict, "whitelist_ips"),
        captcha_secret: string_item(dict, "captcha_secret"),
    }
}
