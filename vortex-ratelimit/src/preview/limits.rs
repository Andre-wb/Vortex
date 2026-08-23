use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const PREVIEWS: u32 = 30;
pub const WINDOW_SECONDS: u64 = 60;

pub fn limit() -> Limit {
    Limit::of(PREVIEWS).expect("предел предпросмотров ссылок задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно предпросмотров ссылок задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, PREVIEWS, WINDOW_SECONDS};

    #[test]
    fn a_minute_holds_thirty_previews_per_identity() {
        assert_eq!(PREVIEWS, 30);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(limit().value(), 30);
        assert_eq!(window().as_seconds(), 60);
    }
}
