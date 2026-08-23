pub const PLACEHOLDER: &str = "{id}";

pub fn endpoint(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit()) {
                PLACEHOLDER
            } else {
                segment
            }
        })
        .collect::<Vec<&str>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::endpoint;

    #[test]
    fn a_numeric_segment_collapses_so_the_label_set_stays_small() {
        assert_eq!(endpoint("/api/rooms/123"), "/api/rooms/{id}");
        assert_eq!(
            endpoint("/api/rooms/123/messages/9"),
            "/api/rooms/{id}/messages/{id}"
        );
    }

    #[test]
    fn a_segment_that_only_starts_with_digits_is_left_alone() {
        assert_eq!(endpoint("/api/12ab"), "/api/12ab");
        assert_eq!(endpoint("/health"), "/health");
        assert_eq!(endpoint("/"), "/");
    }
}
