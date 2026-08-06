use crate::ports::random_source::RandomSource;
use crate::reality::short_id::value::{ShortId, SHORT_ID_LEN};

pub fn generate(random: &dyn RandomSource) -> ShortId {
    ShortId::from_bytes(random.bytes(SHORT_ID_LEN))
}

#[cfg(test)]
mod tests {
    use super::generate;
    use crate::random::fixed_random::FixedRandom;
    use crate::reality::short_id::value::SHORT_ID_HEX_LEN;

    #[test]
    fn produces_an_id_of_the_canonical_length() {
        let random = FixedRandom::new(vec![0x01, 0x02, 0x03, 0x04]);
        let id = generate(&random);
        assert_eq!(id.to_hex(), "01020304");
        assert_eq!(id.to_hex().len(), SHORT_ID_HEX_LEN);
    }
}
