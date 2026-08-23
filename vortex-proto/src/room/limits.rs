pub const NAME_MIN_LEN: usize = 1;

pub const NAME_MAX_LEN: usize = 100;

pub const DESCRIPTION_MAX_LEN: usize = 500;

pub const AVATAR_MAX_LEN: usize = 10;

pub const ALLOWED_REACTIONS_MAX_LEN: usize = 500;

pub const DEFAULT_AVATAR: &str = "\u{1f4ac}";

pub const VOICE_AVATAR: &str = "\u{1f50a}";

pub const DEFAULT_MAX_MEMBERS: i64 = 200;

#[cfg(test)]
mod tests {
    use super::{DEFAULT_AVATAR, NAME_MAX_LEN, NAME_MIN_LEN, VOICE_AVATAR};

    #[test]
    fn a_room_must_be_named_by_at_least_one_character() {
        assert_eq!(NAME_MIN_LEN, 1);
        assert_eq!(NAME_MAX_LEN, 100);
    }

    #[test]
    fn the_two_default_avatars_are_told_apart() {
        assert_ne!(DEFAULT_AVATAR, VOICE_AVATAR);
        assert_eq!(DEFAULT_AVATAR.chars().count(), 1);
        assert_eq!(VOICE_AVATAR.chars().count(), 1);
    }
}
