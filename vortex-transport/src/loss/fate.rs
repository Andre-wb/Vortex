use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;

pub const DEFAULT_LOSS_RATE: f64 = 0.002;
pub const DEFAULT_DUPLICATE_RATE: f64 = 0.001;
pub const RETRANSMIT_MIN: f64 = 0.2;
pub const RETRANSMIT_MAX: f64 = 0.8;
pub const ECHO_MIN: f64 = 0.03;
pub const ECHO_MAX: f64 = 0.08;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fate {
    Delivered,
    Retransmitted(f64),
    Duplicated(f64),
}

impl Fate {
    pub fn copies(&self) -> Vec<f64> {
        match self {
            Fate::Delivered => vec![0.0],
            Fate::Retransmitted(after) => vec![*after],
            Fate::Duplicated(after) => vec![0.0, *after],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LossProfile {
    pub loss_rate: f64,
    pub duplicate_rate: f64,
}

impl Default for LossProfile {
    fn default() -> Self {
        LossProfile {
            loss_rate: DEFAULT_LOSS_RATE,
            duplicate_rate: DEFAULT_DUPLICATE_RATE,
        }
    }
}

impl LossProfile {
    pub fn of(loss_rate: f64, duplicate_rate: f64) -> Self {
        LossProfile {
            loss_rate: loss_rate.clamp(0.0, 1.0),
            duplicate_rate: duplicate_rate.clamp(0.0, 1.0),
        }
    }

    pub fn decide(&self, random: &dyn RandomSource) -> Fate {
        let drawn = uniform::unit(random);
        if drawn < self.loss_rate {
            return Fate::Retransmitted(uniform::range(random, RETRANSMIT_MIN, RETRANSMIT_MAX));
        }
        if drawn < self.loss_rate + self.duplicate_rate {
            return Fate::Duplicated(uniform::range(random, ECHO_MIN, ECHO_MAX));
        }
        Fate::Delivered
    }
}

#[cfg(test)]
mod tests {
    use super::{Fate, LossProfile, ECHO_MAX, ECHO_MIN, RETRANSMIT_MAX, RETRANSMIT_MIN};
    use crate::random::os_random::OsRandom;

    #[test]
    fn almost_every_frame_is_delivered_at_once() {
        let profile = LossProfile::default();
        let random = OsRandom::new();
        let delivered = (0..20_000)
            .filter(|_| profile.decide(&random) == Fate::Delivered)
            .count();
        assert!(delivered > 19_800, "доставлено {delivered} из 20000");
    }

    #[test]
    fn a_frame_that_is_lost_comes_back_after_a_wait_a_retransmission_takes() {
        let profile = LossProfile::of(1.0, 0.0);
        let random = OsRandom::new();
        for _ in 0..500 {
            match profile.decide(&random) {
                Fate::Retransmitted(after) => {
                    assert!((RETRANSMIT_MIN..RETRANSMIT_MAX).contains(&after))
                }
                other => panic!("ожидалась ретрансмиссия, получено {other:?}"),
            }
        }
    }

    #[test]
    fn a_duplicated_frame_is_sent_twice_and_the_echo_follows_closely() {
        let profile = LossProfile::of(0.0, 1.0);
        let random = OsRandom::new();
        match profile.decide(&random) {
            Fate::Duplicated(after) => {
                assert!((ECHO_MIN..ECHO_MAX).contains(&after));
                assert_eq!(Fate::Duplicated(after).copies().len(), 2);
            }
            other => panic!("ожидался дубликат, получено {other:?}"),
        }
    }

    #[test]
    fn a_delivered_frame_is_sent_once_and_without_waiting() {
        assert_eq!(Fate::Delivered.copies(), vec![0.0]);
    }

    #[test]
    fn a_profile_that_loses_nothing_loses_nothing() {
        let profile = LossProfile::of(0.0, 0.0);
        let random = OsRandom::new();
        for _ in 0..2000 {
            assert_eq!(profile.decide(&random), Fate::Delivered);
        }
    }

    #[test]
    fn a_rate_outside_what_a_rate_can_be_is_brought_back_into_it() {
        assert_eq!(LossProfile::of(-1.0, 9.0).loss_rate, 0.0);
        assert_eq!(LossProfile::of(-1.0, 9.0).duplicate_rate, 1.0);
    }
}
