use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const REQUESTS: u32 = 20;
pub const WINDOW_SECONDS: u64 = 60;

pub fn limit() -> Limit {
    Limit::of(REQUESTS).expect("предел обращений к помощнику задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно обращений к помощнику задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, REQUESTS, WINDOW_SECONDS};

    #[test]
    fn a_minute_holds_twenty_requests_to_the_assistant() {
        assert_eq!(REQUESTS, 20);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(limit().value(), 20);
        assert_eq!(window().as_seconds(), 60);
    }
}
