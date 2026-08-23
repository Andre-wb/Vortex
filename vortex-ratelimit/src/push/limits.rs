use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const REGISTRATIONS: u32 = 60;
pub const WAKES: u32 = 600;
pub const WINDOW_SECONDS: u64 = 60;

pub fn registration_limit() -> Limit {
    Limit::of(REGISTRATIONS).expect("предел регистраций push-токена задан ненулевым")
}

pub fn wake_limit() -> Limit {
    Limit::of(WAKES).expect("предел пробуждений задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно push-прокси задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{registration_limit, wake_limit, window, REGISTRATIONS, WAKES, WINDOW_SECONDS};

    #[test]
    fn a_minute_holds_sixty_registrations_and_six_hundred_wakes() {
        assert_eq!(REGISTRATIONS, 60);
        assert_eq!(WAKES, 600);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(registration_limit().value(), 60);
        assert_eq!(wake_limit().value(), 600);
        assert_eq!(window().as_seconds(), 60);
    }
}
