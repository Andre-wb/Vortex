//! Разбор строки запроса и тела `application/x-www-form-urlencoded`.

use crate::domain::param_map::ParamMap;
use crate::util::percent_decode::decode_plus;

/// Аналог `urllib.parse.parse_qs` со значениями по умолчанию: пустые значения
/// отбрасываются, разделитель — только `&`.
pub fn parse_qs(query: &str) -> ParamMap {
    let mut params = ParamMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => continue,
        };
        if raw_value.is_empty() {
            continue;
        }
        let key = decode_plus(raw_key);
        if key.is_empty() {
            continue;
        }
        params.push(key, decode_plus(raw_value));
    }
    params
}

#[cfg(test)]
mod tests {
    use super::parse_qs;

    #[test]
    fn groups_repeated_keys() {
        let params = parse_qs("a=1&a=2&b=3");
        assert_eq!(params.get("a").map(<[String]>::len), Some(2));
        assert_eq!(params.get("b").map(|v| v[0].as_str()), Some("3"));
    }

    #[test]
    fn drops_blank_and_keyless_pairs() {
        let params = parse_qs("a=&novalue&b=2");
        assert!(params.get("a").is_none());
        assert!(params.get("novalue").is_none());
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn decodes_values() {
        let params = parse_qs("q=%3Cscript%3E");
        assert_eq!(params.get("q").map(|v| v[0].as_str()), Some("<script>"));
    }
}
