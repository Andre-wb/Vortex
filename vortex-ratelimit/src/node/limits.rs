use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const REQUESTS: u32 = 100;
pub const WINDOW_SECONDS: u64 = 60;

pub fn limit() -> Limit {
    Limit::of(REQUESTS).expect("предел обращений узла задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно обращений узла задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, REQUESTS, WINDOW_SECONDS};

    #[test]
    fn a_minute_holds_a_hundred_requests_from_one_node() {
        assert_eq!(REQUESTS, 100);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(limit().value(), 100);
        assert_eq!(window().as_seconds(), 60);
    }
}
