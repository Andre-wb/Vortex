use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const REQUESTS: u32 = 10;
pub const WINDOW_SECONDS: u64 = 60;

pub fn limit() -> Limit {
    Limit::of(REQUESTS).expect("предел пакетов сплетен задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно пакетов сплетен задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, REQUESTS, WINDOW_SECONDS};

    #[test]
    fn a_minute_holds_ten_packets_from_one_address() {
        assert_eq!(REQUESTS, 10);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(limit().value(), 10);
        assert_eq!(window().as_seconds(), 60);
    }
}
