pub const BUCKETS: &[u32] = &[128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];
pub const PROMOTE_PROBABILITY: f64 = 0.15;
pub const TILE_STEP: u32 = 8192;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PaddingLadder {
    pub enabled: bool,
    pub promote_probability: f64,
    pub tile_step: u32,
}

impl Default for PaddingLadder {
    fn default() -> Self {
        PaddingLadder {
            enabled: true,
            promote_probability: PROMOTE_PROBABILITY,
            tile_step: TILE_STEP,
        }
    }
}

impl PaddingLadder {
    pub fn buckets(&self) -> Vec<u32> {
        BUCKETS.to_vec()
    }

    pub fn target_for(&self, length: u32) -> u32 {
        match BUCKETS.iter().find(|bucket| **bucket >= length) {
            Some(bucket) => *bucket,
            None => length.div_ceil(self.tile_step) * self.tile_step,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PaddingLadder, BUCKETS, TILE_STEP};

    #[test]
    fn the_ladder_climbs_and_never_repeats_a_step() {
        assert!(BUCKETS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn a_length_is_padded_up_to_the_first_step_that_holds_it() {
        let ladder = PaddingLadder::default();
        assert_eq!(ladder.target_for(1), 128);
        assert_eq!(ladder.target_for(128), 128);
        assert_eq!(ladder.target_for(129), 256);
        assert_eq!(ladder.target_for(65536), 65536);
    }

    #[test]
    fn a_length_above_the_ladder_is_padded_up_to_a_whole_tile() {
        let ladder = PaddingLadder::default();
        assert_eq!(ladder.target_for(65537), 65536 + TILE_STEP);
        assert_eq!(ladder.target_for(65536 + TILE_STEP), 65536 + TILE_STEP);
        assert_eq!(
            ladder.target_for(65536 + TILE_STEP + 1),
            65536 + 2 * TILE_STEP
        );
    }

    #[test]
    fn the_padded_length_is_never_shorter_than_what_was_padded() {
        let ladder = PaddingLadder::default();
        for length in [1u32, 127, 1000, 65535, 70000, 200000] {
            assert!(ladder.target_for(length) >= length, "{length}");
        }
    }

    #[test]
    fn a_step_up_happens_sometimes_but_not_usually() {
        let ladder = PaddingLadder::default();
        assert!(ladder.promote_probability > 0.0);
        assert!(ladder.promote_probability < 0.5);
    }
}
