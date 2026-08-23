use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const LOGINS: u32 = 30;
pub const WINDOW_SECONDS: u64 = 60;

pub fn limit() -> Limit {
    Limit::of(LOGINS).expect("предел гостевых входов задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно гостевых входов задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, LOGINS, WINDOW_SECONDS};

    #[test]
    fn a_minute_holds_thirty_guest_logins_from_one_address() {
        assert_eq!(LOGINS, 30);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(limit().value(), 30);
        assert_eq!(window().as_seconds(), 60);
    }
}
