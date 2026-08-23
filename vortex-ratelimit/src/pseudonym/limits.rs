use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const RESOLVES: u32 = 100;
pub const WINDOW_SECONDS: u64 = 60;

pub fn operator_limit(resolves: u32) -> Option<Limit> {
    Limit::of(resolves)
}

pub fn operator_window(seconds: u64) -> Option<Window> {
    Window::seconds(seconds)
}

#[cfg(test)]
mod tests {
    use super::{operator_limit, operator_window, RESOLVES, WINDOW_SECONDS};

    #[test]
    fn the_shipped_defaults_are_a_hundred_resolves_a_minute() {
        assert_eq!(RESOLVES, 100);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(operator_limit(RESOLVES).unwrap().value(), 100);
        assert_eq!(operator_window(WINDOW_SECONDS).unwrap().as_seconds(), 60);
    }

    #[test]
    fn neither_a_zero_limit_nor_a_zero_window_can_count_anything() {
        assert!(operator_limit(0).is_none());
        assert!(operator_window(0).is_none());
    }
}
