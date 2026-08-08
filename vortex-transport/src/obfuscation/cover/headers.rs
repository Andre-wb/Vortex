pub const COVER_HEADERS: [(&str, &str); 3] = [
    ("Server", "nginx/1.24.0"),
    ("X-Powered-By", "Express"),
    ("Vary", "Accept-Encoding"),
];

#[cfg(test)]
mod tests {
    use super::COVER_HEADERS;

    #[test]
    fn the_cover_story_is_a_reverse_proxy_in_front_of_an_application() {
        let names: Vec<&str> = COVER_HEADERS.iter().map(|(name, _)| *name).collect();
        assert!(names.contains(&"Server"));
        assert!(names.contains(&"X-Powered-By"));
    }

    #[test]
    fn no_header_is_told_twice() {
        let mut names: Vec<&str> = COVER_HEADERS.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn nothing_in_the_cover_story_is_empty() {
        assert!(COVER_HEADERS
            .iter()
            .all(|(name, value)| !name.is_empty() && !value.is_empty()));
    }
}
