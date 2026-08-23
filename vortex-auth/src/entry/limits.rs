use vortex_ratelimit::attempt::limit::Limit;
use vortex_ratelimit::attempt::window::Window;

pub const LOGIN_ATTEMPTS: u32 = 10;
pub const REGISTRATION_ATTEMPTS: u32 = 5;
pub const WINDOW_SECONDS: u64 = 60;

pub fn login_limit() -> Limit {
    Limit::of(LOGIN_ATTEMPTS).expect("предел попыток входа задан ненулевым")
}

pub fn registration_limit() -> Limit {
    Limit::of(REGISTRATION_ATTEMPTS).expect("предел попыток регистрации задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно попыток входа задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{
        login_limit, registration_limit, window, LOGIN_ATTEMPTS, REGISTRATION_ATTEMPTS,
        WINDOW_SECONDS,
    };

    #[test]
    fn a_minute_holds_ten_logins_and_five_registrations() {
        assert_eq!(LOGIN_ATTEMPTS, 10);
        assert_eq!(REGISTRATION_ATTEMPTS, 5);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(login_limit().value(), 10);
        assert_eq!(registration_limit().value(), 5);
        assert_eq!(window().as_seconds(), 60);
    }
}
