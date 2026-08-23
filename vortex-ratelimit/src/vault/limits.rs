use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const READS: u32 = 30;
pub const WINDOW_SECONDS: u64 = 60;

pub fn limit() -> Limit {
    Limit::of(READS).expect("предел чтений профиль-хранилища задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно чтений профиль-хранилища задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, READS, WINDOW_SECONDS};

    #[test]
    fn a_minute_holds_thirty_profile_lookups() {
        assert_eq!(READS, 30);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(limit().value(), 30);
        assert_eq!(window().as_seconds(), 60);
    }
}
