use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const TRANSLATIONS: u32 = 50;
pub const WINDOW_SECONDS: u64 = 3600;

pub fn limit() -> Limit {
    Limit::of(TRANSLATIONS).expect("предел переводов задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно переводов задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, TRANSLATIONS, WINDOW_SECONDS};

    #[test]
    fn an_hour_holds_fifty_translations() {
        assert_eq!(TRANSLATIONS, 50);
        assert_eq!(WINDOW_SECONDS, 3600);
        assert_eq!(limit().value(), 50);
        assert_eq!(window().as_seconds(), 3600);
    }
}
