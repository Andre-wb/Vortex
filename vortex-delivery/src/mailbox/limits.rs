pub const ROOM_DEPTH: usize = 1000;
pub const ROOM_LIFETIME_SECONDS: f64 = 604_800.0;

pub const NOTIFICATION_DEPTH: usize = 50;
pub const NOTIFICATION_LIFETIME_SECONDS: f64 = 300.0;

#[cfg(test)]
mod tests {
    use super::{
        NOTIFICATION_DEPTH, NOTIFICATION_LIFETIME_SECONDS, ROOM_DEPTH, ROOM_LIFETIME_SECONDS,
    };

    #[test]
    fn the_room_queue_keeps_a_thousand_for_a_week() {
        assert_eq!(ROOM_DEPTH, 1000);
        assert_eq!(ROOM_LIFETIME_SECONDS, 7.0 * 86_400.0);
    }

    #[test]
    fn the_notification_queue_keeps_fifty_for_five_minutes() {
        assert_eq!(NOTIFICATION_DEPTH, 50);
        assert_eq!(NOTIFICATION_LIFETIME_SECONDS, 5.0 * 60.0);
    }
}
