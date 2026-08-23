use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const POSTS: u32 = 120;
pub const WINDOW_SECONDS: u64 = 60;

pub fn limit() -> Limit {
    Limit::of(POSTS).expect("предел принимаемых конвертов задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно принимаемых конвертов задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, POSTS, WINDOW_SECONDS};

    #[test]
    fn a_minute_holds_a_hundred_and_twenty_envelopes_from_one_address() {
        assert_eq!(POSTS, 120);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(limit().value(), 120);
        assert_eq!(window().as_seconds(), 60);
    }
}
