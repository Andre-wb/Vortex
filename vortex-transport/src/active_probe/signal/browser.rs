use crate::active_probe::request::headers::HeaderSet;
use crate::active_probe::signal::kind::Signal;

pub const ALWAYS_SENT: [&str; 6] = [
    "accept",
    "accept-language",
    "accept-encoding",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-dest",
];

pub fn read(headers: &HeaderSet, enough: usize) -> Option<Signal> {
    let missing = headers.missing_from(&ALWAYS_SENT);
    if missing >= enough {
        return Some(Signal::MissingBrowserHeaders(missing));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{read, ALWAYS_SENT};
    use crate::active_probe::request::headers::HeaderSet;
    use crate::active_probe::signal::kind::Signal;

    fn browser() -> HeaderSet {
        HeaderSet::of(ALWAYS_SENT.map(|name| (name, "x")))
    }

    #[test]
    fn a_client_that_sends_what_a_browser_sends_raises_nothing() {
        assert_eq!(read(&browser(), 4), None);
    }

    #[test]
    fn a_client_that_sends_almost_nothing_a_browser_sends_is_counted() {
        let bare = HeaderSet::of([("accept", "*/*"), ("accept-encoding", "gzip")]);
        assert_eq!(read(&bare, 4), Some(Signal::MissingBrowserHeaders(4)));
        assert_eq!(
            read(&HeaderSet::default(), 4),
            Some(Signal::MissingBrowserHeaders(6))
        );
    }

    #[test]
    fn one_header_short_of_the_threshold_is_not_a_signal() {
        let three = HeaderSet::of([
            ("accept", "*/*"),
            ("accept-encoding", "gzip"),
            ("accept-language", "ru"),
        ]);
        assert_eq!(read(&three, 4), None);
    }
}
