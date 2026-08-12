use crate::active_probe::signal::kind::Signal;

pub const ANYTHING: &str = "/*";

pub fn read(path: &str, accept: &str) -> Option<Signal> {
    let expected = expected_for(path)?;
    if accept.contains(expected) || accept.contains(ANYTHING) {
        return None;
    }
    Some(Signal::AcceptMismatch)
}

fn expected_for(path: &str) -> Option<&'static str> {
    if path.ends_with(".js") {
        return Some("javascript");
    }
    if path.ends_with(".css") {
        return Some("text/css");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::read;
    use crate::active_probe::signal::kind::Signal;

    #[test]
    fn a_path_that_asks_for_no_particular_type_raises_nothing() {
        assert_eq!(read("/health", ""), None);
        assert_eq!(read("/", "text/html"), None);
        assert_eq!(read("/api/chats", "application/json"), None);
    }

    #[test]
    fn a_browser_asking_for_a_script_says_so() {
        assert_eq!(read("/static/js/app.js", "*/*"), None);
        assert_eq!(read("/static/js/app.js", "text/javascript,*/*;q=0.1"), None);
    }

    #[test]
    fn a_client_fetching_a_script_it_does_not_accept_is_a_signal() {
        assert_eq!(
            read("/static/js/app.js", "text/html"),
            Some(Signal::AcceptMismatch)
        );
        assert_eq!(
            read("/static/css/app.css", ""),
            Some(Signal::AcceptMismatch)
        );
    }

    #[test]
    fn a_stylesheet_is_judged_by_its_own_type_and_not_by_the_type_of_a_script() {
        assert_eq!(read("/static/css/app.css", "text/css"), None);
        assert_eq!(
            read("/static/css/app.css", "javascript"),
            Some(Signal::AcceptMismatch)
        );
    }
}
