use crate::active_probe::request::head::RequestHead;
use crate::active_probe::signal::kind::Signal;

pub const FIRST_VISIT: &str = "/";

pub fn read(request: &RequestHead) -> Option<Signal> {
    if request.carries_cookies() || request.path() == FIRST_VISIT {
        return None;
    }
    Some(Signal::NoCookies)
}

#[cfg(test)]
mod tests {
    use super::read;
    use crate::active_probe::request::head::RequestHead;
    use crate::active_probe::request::headers::HeaderSet;
    use crate::active_probe::signal::kind::Signal;

    fn request(path: &str, headers: HeaderSet) -> RequestHead {
        RequestHead::new("203.0.113.7", "GET", path, headers)
    }

    #[test]
    fn a_client_that_has_been_here_before_raises_nothing() {
        let carried = HeaderSet::of([("cookie", "session=1")]);
        assert_eq!(read(&request("/api/chats", carried)), None);
    }

    #[test]
    fn nobody_has_a_cookie_on_the_first_page_they_open() {
        assert_eq!(read(&request("/", HeaderSet::default())), None);
    }

    #[test]
    fn a_client_reaching_past_the_front_page_without_a_cookie_is_a_signal() {
        assert_eq!(
            read(&request("/api/chats", HeaderSet::default())),
            Some(Signal::NoCookies)
        );
    }
}
