use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const WINDOW_SECONDS: u64 = 3600;

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно выдачи транспортных паролей задано ненулевым")
}

pub fn operator_limit(requests: u32) -> Option<Limit> {
    Limit::of(requests)
}

#[cfg(test)]
mod tests {
    use super::{operator_limit, window, WINDOW_SECONDS};

    #[test]
    fn the_window_is_an_hour_wide() {
        assert_eq!(WINDOW_SECONDS, 3600);
        assert_eq!(window().as_seconds(), 3600);
    }

    #[test]
    fn the_operator_names_the_limit_and_zero_names_nobody() {
        assert_eq!(operator_limit(10).unwrap().value(), 10);
        assert!(operator_limit(0).is_none());
    }
}
