use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderSet {
    fields: BTreeMap<String, String>,
}

impl HeaderSet {
    pub fn of<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut set = HeaderSet::default();
        for (name, value) in fields {
            set.put(name, value);
        }
        set
    }

    pub fn put(&mut self, name: &str, value: &str) {
        self.fields
            .insert(name.trim().to_ascii_lowercase(), value.to_owned());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    pub fn value(&self, name: &str) -> &str {
        self.get(name).unwrap_or_default()
    }

    pub fn has(&self, name: &str) -> bool {
        self.fields.contains_key(name)
    }

    pub fn missing_from(&self, expected: &[&str]) -> usize {
        expected.iter().filter(|name| !self.has(name)).count()
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::HeaderSet;

    #[test]
    fn a_header_is_found_however_the_client_spelled_its_name() {
        let headers = HeaderSet::of([("User-Agent", "curl/8"), ("ACCEPT", "*/*")]);
        assert_eq!(headers.get("user-agent"), Some("curl/8"));
        assert_eq!(headers.get("accept"), Some("*/*"));
        assert!(headers.has("user-agent"));
    }

    #[test]
    fn a_header_nobody_sent_reads_as_the_empty_value() {
        let headers = HeaderSet::of([("host", "example.org")]);
        assert_eq!(headers.get("cookie"), None);
        assert_eq!(headers.value("cookie"), "");
        assert!(!headers.has("cookie"));
    }

    #[test]
    fn a_header_sent_twice_keeps_the_value_that_came_last() {
        let headers = HeaderSet::of([("accept", "text/html"), ("Accept", "*/*")]);
        assert_eq!(headers.get("accept"), Some("*/*"));
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn the_headers_a_browser_always_sends_are_counted_when_they_are_absent() {
        let expected = ["accept", "accept-language", "sec-fetch-mode"];
        let headers = HeaderSet::of([("accept", "*/*")]);
        assert_eq!(headers.missing_from(&expected), 2);
        assert_eq!(HeaderSet::default().missing_from(&expected), 3);
    }
}
