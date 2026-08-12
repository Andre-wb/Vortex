use crate::active_probe::request::headers::HeaderSet;
use crate::net::address;
use crate::net::local;
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub struct RequestHead {
    peer: String,
    method: String,
    path: String,
    headers: HeaderSet,
}

impl RequestHead {
    pub fn new(peer: &str, method: &str, path: &str, headers: HeaderSet) -> Self {
        RequestHead {
            peer: peer.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            headers,
        }
    }

    pub fn peer(&self) -> &str {
        &self.peer
    }

    pub fn address(&self) -> Option<IpAddr> {
        address::parse(&self.peer)
    }

    pub fn is_local(&self) -> bool {
        self.address()
            .map(|at| local::is_local(&at))
            .unwrap_or(false)
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn headers(&self) -> &HeaderSet {
        &self.headers
    }

    pub fn user_agent(&self) -> &str {
        self.headers.value("user-agent")
    }

    pub fn accept(&self) -> &str {
        self.headers.value("accept")
    }

    pub fn carries_cookies(&self) -> bool {
        self.headers.has("cookie")
    }
}

#[cfg(test)]
mod tests {
    use super::RequestHead;
    use crate::active_probe::request::headers::HeaderSet;

    fn head(peer: &str) -> RequestHead {
        RequestHead::new(
            peer,
            "GET",
            "/health",
            HeaderSet::of([("User-Agent", "curl/8")]),
        )
    }

    #[test]
    fn the_request_carries_what_the_signals_ask_it_for() {
        let request = head("203.0.113.7");
        assert_eq!(request.method(), "GET");
        assert_eq!(request.path(), "/health");
        assert_eq!(request.user_agent(), "curl/8");
        assert_eq!(request.accept(), "");
        assert!(!request.carries_cookies());
    }

    #[test]
    fn a_client_on_this_machine_or_this_network_is_known_to_be_local() {
        assert!(head("127.0.0.1").is_local());
        assert!(head("::ffff:127.0.0.1").is_local());
        assert!(head("192.168.1.5").is_local());
        assert!(!head("203.0.113.7").is_local());
    }

    #[test]
    fn a_peer_whose_address_cannot_be_read_is_not_taken_for_a_local_one() {
        assert!(!head("").is_local());
        assert!(!head("localhost").is_local());
        assert_eq!(head("").address(), None);
    }
}
