use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const STORES: u32 = 120;
pub const WINDOW_SECONDS: u64 = 60;

pub fn limit() -> Limit {
    Limit::of(STORES).expect("предел сохранений долей задан ненулевым")
}

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно сохранений долей задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{limit, window, STORES, WINDOW_SECONDS};

    #[test]
    fn a_minute_holds_one_hundred_and_twenty_shard_stores_from_one_address() {
        assert_eq!(STORES, 120);
        assert_eq!(WINDOW_SECONDS, 60);
        assert_eq!(limit().value(), 120);
        assert_eq!(window().as_seconds(), 60);
    }
}
