use crate::active_probe::request::head::RequestHead;
use sha2::{Digest, Sha256};

pub const WIDTH: usize = 16;

pub fn of(request: &RequestHead) -> String {
    let mut digest = Sha256::new();
    for field in [
        request.peer(),
        request.method(),
        request.path(),
        request.user_agent(),
        request.accept(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    hex_of(&digest.finalize()[..WIDTH / 2])
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{of, WIDTH};
    use crate::active_probe::request::head::RequestHead;
    use crate::active_probe::request::headers::HeaderSet;

    fn request(peer: &str, path: &str, agent: &str) -> RequestHead {
        RequestHead::new(
            peer,
            "GET",
            path,
            HeaderSet::of([("user-agent", agent), ("accept", "*/*")]),
        )
    }

    #[test]
    fn the_same_request_from_the_same_client_has_the_same_fingerprint() {
        let first = of(&request("203.0.113.7", "/health", "curl/8"));
        let second = of(&request("203.0.113.7", "/health", "curl/8"));
        assert_eq!(first, second);
        assert_eq!(first.len(), WIDTH);
    }

    #[test]
    fn changing_any_part_of_the_request_changes_the_fingerprint() {
        let base = of(&request("203.0.113.7", "/health", "curl/8"));
        assert_ne!(base, of(&request("203.0.113.8", "/health", "curl/8")));
        assert_ne!(base, of(&request("203.0.113.7", "/metrics", "curl/8")));
        assert_ne!(base, of(&request("203.0.113.7", "/health", "wget/1")));
    }

    #[test]
    fn two_requests_that_differ_only_in_where_a_separator_falls_are_not_one_request() {
        let split = RequestHead::new("203.0.113.7", "GET", "/a:b", HeaderSet::default());
        let moved = RequestHead::new("203.0.113.7", "GET:/a", "b", HeaderSet::default());
        assert_ne!(of(&split), of(&moved));
    }

    #[test]
    fn an_empty_field_is_not_the_same_as_a_field_that_was_shifted_into_its_neighbour() {
        let empty_agent = RequestHead::new("1.2.3.4", "GET", "/ab", HeaderSet::default());
        let shifted =
            RequestHead::new("1.2.3.4", "GET", "/a", HeaderSet::of([("user-agent", "b")]));
        assert_ne!(of(&empty_agent), of(&shifted));
    }
}
