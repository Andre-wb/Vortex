use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const REPEATS: u32 = 3;
pub const REPEAT_WINDOW_SECONDS: u64 = 30;
pub const LINKS: u32 = 3;
pub const LINK_WINDOW_SECONDS: u64 = 60;

pub fn repeats() -> u32 {
    REPEATS
}

pub fn repeat_window() -> Window {
    Window::seconds(REPEAT_WINDOW_SECONDS).expect("окно повторов задано ненулевым")
}

pub fn link_limit() -> Limit {
    Limit::of(LINKS - 1).expect("предел ссылок задан ненулевым")
}

pub fn link_window() -> Window {
    Window::seconds(LINK_WINDOW_SECONDS).expect("окно ссылок задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{
        link_limit, link_window, repeat_window, repeats, LINKS, LINK_WINDOW_SECONDS, REPEATS,
        REPEAT_WINDOW_SECONDS,
    };

    #[test]
    fn half_a_minute_holds_two_copies_of_one_message_and_the_third_is_spam() {
        assert_eq!(REPEATS, 3);
        assert_eq!(REPEAT_WINDOW_SECONDS, 30);
        assert_eq!(repeats(), 3);
        assert_eq!(repeat_window().as_seconds(), 30);
    }

    #[test]
    fn the_third_link_in_a_minute_is_spam_so_only_two_pass() {
        assert_eq!(LINKS, 3);
        assert_eq!(LINK_WINDOW_SECONDS, 60);
        assert_eq!(link_limit().value(), 2);
        assert_eq!(link_window().as_seconds(), 60);
    }
}
