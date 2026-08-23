#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VirtualRoomId(i64);

impl VirtualRoomId {
    pub fn of(value: i64) -> Option<Self> {
        if value >= 0 {
            return None;
        }
        Some(VirtualRoomId(value))
    }

    pub fn value(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::VirtualRoomId;

    #[test]
    fn a_virtual_room_is_named_by_a_negative_number() {
        assert_eq!(VirtualRoomId::of(-1).unwrap().value(), -1);
    }

    #[test]
    fn zero_and_above_name_a_local_room_not_a_virtual_one() {
        assert!(VirtualRoomId::of(0).is_none());
        assert!(VirtualRoomId::of(1).is_none());
    }
}
