pub const MIN_CIPHERTEXT_HEX: usize = 48;

pub const MAX_CIPHERTEXT_HEX: usize = 65_536;

pub const MAX_FRAME_TEXT: usize = 65_536;

pub const MAX_MENTIONS: usize = 20;

pub const MENTION_MIN_LEN: usize = 3;

pub const MENTION_MAX_LEN: usize = 30;

pub const CLIENT_STAMP_WINDOW_SECS: i64 = 300;

#[cfg(test)]
mod tests {
    use super::{CLIENT_STAMP_WINDOW_SECS, MAX_CIPHERTEXT_HEX, MAX_FRAME_TEXT, MIN_CIPHERTEXT_HEX};

    #[test]
    fn the_shortest_ciphertext_is_a_nonce_and_a_tag_short_of_nothing() {
        assert_eq!(MIN_CIPHERTEXT_HEX / 2, 24);
    }

    #[test]
    fn a_ciphertext_can_fill_the_whole_frame_but_no_more() {
        assert_eq!(MAX_CIPHERTEXT_HEX, MAX_FRAME_TEXT);
    }

    #[test]
    fn the_client_stamp_window_is_five_minutes_each_way() {
        assert_eq!(CLIENT_STAMP_WINDOW_SECS, 5 * 60);
    }
}
