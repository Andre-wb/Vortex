pub const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
pub const UA_BRANDS: &str =
    "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"";
pub const PLATFORM: &str = "\"Windows\"";
pub const ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
pub const ACCEPT_ENCODING: &str = "gzip, deflate, br";
pub const ACCEPT_LANGUAGE: &str = "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7";

pub fn navigation(host: &str, referer: &str, cookies: &str) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = vec![
        ("Host".to_owned(), host.to_owned()),
        ("sec-ch-ua".to_owned(), UA_BRANDS.to_owned()),
        ("sec-ch-ua-mobile".to_owned(), "?0".to_owned()),
        ("sec-ch-ua-platform".to_owned(), PLATFORM.to_owned()),
        ("Upgrade-Insecure-Requests".to_owned(), "1".to_owned()),
        ("User-Agent".to_owned(), UA.to_owned()),
        ("Accept".to_owned(), ACCEPT.to_owned()),
        ("Sec-Fetch-Site".to_owned(), "none".to_owned()),
        ("Sec-Fetch-Mode".to_owned(), "navigate".to_owned()),
        ("Sec-Fetch-User".to_owned(), "?1".to_owned()),
        ("Sec-Fetch-Dest".to_owned(), "document".to_owned()),
    ];
    if !referer.is_empty() {
        fields.push(("Referer".to_owned(), referer.to_owned()));
    }
    fields.push(("Accept-Encoding".to_owned(), ACCEPT_ENCODING.to_owned()));
    fields.push(("Accept-Language".to_owned(), ACCEPT_LANGUAGE.to_owned()));
    if !cookies.is_empty() {
        fields.push(("Cookie".to_owned(), cookies.to_owned()));
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::navigation;
    use crate::headers::order;

    fn names(fields: &[(String, String)]) -> Vec<String> {
        fields.iter().map(|(name, _)| name.clone()).collect()
    }

    #[test]
    fn the_set_a_browser_sends_is_already_in_the_order_a_browser_sends_it() {
        let fields = navigation("example.org", "https://www.google.com/", "a=1");
        assert_eq!(names(&order::arrange(&fields)), names(&fields));
    }

    #[test]
    fn a_visit_with_no_history_carries_neither_a_referer_nor_a_cookie() {
        let fields = navigation("example.org", "", "");
        let sent = names(&fields);
        assert!(!sent.contains(&"Referer".to_owned()));
        assert!(!sent.contains(&"Cookie".to_owned()));
    }

    #[test]
    fn a_visit_with_history_carries_both() {
        let fields = navigation("example.org", "https://yandex.ru/", "_ga=1");
        let sent = names(&fields);
        assert!(sent.contains(&"Referer".to_owned()));
        assert!(sent.contains(&"Cookie".to_owned()));
    }

    #[test]
    fn the_host_is_the_one_that_was_asked_for() {
        let fields = navigation("vortex.example", "", "");
        assert_eq!(fields[0], ("Host".to_owned(), "vortex.example".to_owned()));
    }

    #[test]
    fn every_header_a_probe_looks_for_is_present() {
        let fields = navigation("example.org", "", "");
        let sent: Vec<String> = names(&fields)
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        for expected in crate::active_probe::signal::browser::ALWAYS_SENT {
            assert!(sent.contains(&expected.to_owned()), "нет {expected}");
        }
    }
}
