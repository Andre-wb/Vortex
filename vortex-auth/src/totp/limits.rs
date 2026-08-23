use vortex_ratelimit::attempt::limit::Limit;
use vortex_ratelimit::attempt::window::Window;

pub const ATTEMPTS: u32 = 5;
pub const WINDOW_SECONDS: u64 = 300;

pub fn limit() -> Limit {
    Limit::of(ATTEMPTS).expect("предел попыток второго фактора задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно попыток второго фактора задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, ATTEMPTS, WINDOW_SECONDS};

    #[test]
    fn five_minutes_hold_five_attempts_at_the_code() {
        assert_eq!(ATTEMPTS, 5);
        assert_eq!(WINDOW_SECONDS, 300);
        assert_eq!(limit().value(), 5);
        assert_eq!(window().as_seconds(), 300);
    }
}
