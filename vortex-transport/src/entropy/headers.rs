pub const CONTENT_ENCODING: &str = "gzip";
pub const CONTENT_TYPE: &str = "text/html; charset=utf-8";
pub const VARY: &str = "Accept-Encoding";

pub fn describing() -> Vec<(String, String)> {
    vec![
        ("Content-Encoding".to_owned(), CONTENT_ENCODING.to_owned()),
        ("Content-Type".to_owned(), CONTENT_TYPE.to_owned()),
        ("Vary".to_owned(), VARY.to_owned()),
    ]
}

#[cfg(test)]
mod tests {
    use super::describing;

    #[test]
    fn the_headers_say_the_body_is_a_compressed_page() {
        let headers = describing();
        assert_eq!(headers[0].1, "gzip");
        assert!(headers[1].1.starts_with("text/html"));
    }

    #[test]
    fn a_cache_is_told_the_body_depends_on_what_the_client_accepts() {
        assert!(describing().iter().any(|(name, _)| name == "Vary"));
    }
}
