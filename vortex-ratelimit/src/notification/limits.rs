use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const FROM_SENDER: u32 = 60;
pub const TO_PAIR: u32 = 20;
pub const WINDOW_SECONDS: u64 = 60;

pub fn sender_limit() -> Limit {
    Limit::of(FROM_SENDER).expect("предел уведомлений от отправителя задан ненулевым")
}

pub fn pair_limit() -> Limit {
    Limit::of(TO_PAIR).expect("предел уведомлений одному получателю задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно уведомлений задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{pair_limit, sender_limit, window, FROM_SENDER, TO_PAIR, WINDOW_SECONDS};

    #[test]
    fn a_minute_holds_sixty_notifications_and_twenty_to_one_recipient() {
        assert_eq!(FROM_SENDER, 60);
        assert_eq!(TO_PAIR, 20);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(sender_limit().value(), 60);
        assert_eq!(pair_limit().value(), 20);
        assert_eq!(window().as_seconds(), 60);
    }
}
