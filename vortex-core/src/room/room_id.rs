#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoomId(i64);

impl RoomId {
    pub fn of(value: i64) -> Option<Self> {
        if value <= 0 {
            return None;
        }
        Some(RoomId(value))
    }

    pub fn value(self) -> i64 {
        self.0
    }

    pub fn written(self) -> String {
        self.0.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::RoomId;

    #[test]
    fn a_room_is_named_by_a_positive_number() {
        assert_eq!(RoomId::of(7).unwrap().value(), 7);
        assert_eq!(RoomId::of(7).unwrap().written(), "7");
    }

    #[test]
    fn zero_and_below_name_no_room() {
        assert!(RoomId::of(0).is_none());
        assert!(RoomId::of(-1).is_none());
    }
}
