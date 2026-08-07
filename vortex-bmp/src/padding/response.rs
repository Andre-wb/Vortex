use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::ports::random_source::RandomSource;
use crate::random::uniform;

pub const MIN_PADDING_BYTES: usize = 128;
pub const PADDING_SPAN_BYTES: u32 = 384;

pub fn response_padding(random: &dyn RandomSource) -> String {
    let extra = uniform::below(random, PADDING_SPAN_BYTES) as usize;
    let mut bytes = vec![0u8; MIN_PADDING_BYTES + extra];
    random.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::{response_padding, MIN_PADDING_BYTES, PADDING_SPAN_BYTES};
    use crate::random::os_random::OsRandom;

    fn decoded_len(padding: &str) -> usize {
        padding.len() * 3 / 4
    }

    #[test]
    fn the_padding_hides_the_real_response_size() {
        let random = OsRandom::new();
        let lengths: Vec<usize> = (0..64).map(|_| response_padding(&random).len()).collect();
        assert!(lengths.iter().any(|length| length != &lengths[0]));
    }

    #[test]
    fn the_padding_stays_inside_the_configured_range() {
        let random = OsRandom::new();
        for _ in 0..256 {
            let length = decoded_len(&response_padding(&random));
            assert!(length >= MIN_PADDING_BYTES);
            assert!(length < MIN_PADDING_BYTES + PADDING_SPAN_BYTES as usize);
        }
    }

    #[test]
    fn the_padding_is_url_safe() {
        let random = OsRandom::new();
        for _ in 0..64 {
            let padding = response_padding(&random);
            assert!(padding
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
        }
    }
}
