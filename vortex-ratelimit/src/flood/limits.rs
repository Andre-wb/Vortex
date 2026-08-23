use crate::attempt::limit::Limit;
use crate::attempt::window::Window;

pub const DEFAULT_THRESHOLD: u32 = 15;
pub const WINDOW_SECONDS: u64 = 10;
pub const BAN_STRIKES: u32 = 3;

pub fn window() -> Window {
    Window::seconds(WINDOW_SECONDS).expect("окно флуд-контроля задано ненулевым")
}

pub fn threshold(configured: i64) -> Limit {
    let value = u32::try_from(configured).unwrap_or(0);
    let effective = if value == 0 { DEFAULT_THRESHOLD } else { value };
    Limit::of(effective).expect("порог флуда задан ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{threshold, window, BAN_STRIKES, DEFAULT_THRESHOLD, WINDOW_SECONDS};

    #[test]
    fn ten_seconds_hold_fifteen_messages_and_three_penalties_earn_a_ban() {
        assert_eq!(DEFAULT_THRESHOLD, 15);
        assert_eq!(WINDOW_SECONDS, 10);
        assert_eq!(BAN_STRIKES, 3);
        assert_eq!(window().as_seconds(), 10);
    }

    #[test]
    fn the_room_names_its_own_threshold() {
        for configured in [5, 10, 15] {
            assert_eq!(threshold(configured).value(), configured as u32);
        }
    }

    #[test]
    fn a_threshold_no_room_could_offer_falls_back_to_the_default() {
        for configured in [0, -1, -15, i64::MIN, i64::MAX] {
            assert_eq!(threshold(configured).value(), DEFAULT_THRESHOLD);
        }
    }
}
