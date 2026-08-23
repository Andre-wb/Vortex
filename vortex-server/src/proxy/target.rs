use http::Uri;

pub fn path_and_query(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string())
}

#[cfg(test)]
mod tests {
    use http::Uri;

    use super::path_and_query;

    #[test]
    fn the_query_string_travels_with_the_path() {
        let uri: Uri = "http://edge/api/rooms?limit=10".parse().unwrap();
        assert_eq!(path_and_query(&uri), "/api/rooms?limit=10");
    }

    #[test]
    fn a_bare_path_stays_a_bare_path() {
        let uri: Uri = "/health".parse().unwrap();
        assert_eq!(path_and_query(&uri), "/health");
    }
}
