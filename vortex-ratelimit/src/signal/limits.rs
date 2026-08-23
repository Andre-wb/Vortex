use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const MESSAGES: u32 = 100;
pub const WINDOW_SECONDS: u64 = 1;

pub fn limit() -> Limit {
    Limit::of(MESSAGES).expect("предел сигнальных сообщений задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно сигнальных сообщений задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, MESSAGES, WINDOW_SECONDS};

    #[test]
    fn a_second_holds_one_hundred_signalling_messages_from_one_account() {
        assert_eq!(MESSAGES, 100);
        assert_eq!(WINDOW_SECONDS, 1);
        assert_eq!(limit().value(), 100);
        assert_eq!(window().as_seconds(), 1);
    }
}
