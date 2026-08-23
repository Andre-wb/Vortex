pub const PRESENCE_SECONDS: u32 = 120;
pub const RENEWAL_SECONDS: u32 = 30;
pub const RING_SECONDS: u32 = 30;
pub const SCHEDULE_SECONDS: u32 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lifetime(u32);

impl Lifetime {
    pub fn seconds(value: u32) -> Option<Self> {
        if value == 0 {
            return None;
        }
        Some(Lifetime(value))
    }

    pub fn as_seconds(self) -> u32 {
        self.0
    }

    pub fn expires_at(self, now: f64) -> f64 {
        now + self.0 as f64
    }
}

pub fn presence() -> Lifetime {
    Lifetime(PRESENCE_SECONDS)
}

pub fn ring() -> Lifetime {
    Lifetime(RING_SECONDS)
}

pub fn schedule() -> Lifetime {
    Lifetime(SCHEDULE_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::{presence, ring, schedule, Lifetime, RENEWAL_SECONDS};

    #[test]
    fn a_record_lives_two_minutes_without_being_renewed() {
        assert_eq!(presence().as_seconds(), 120);
        assert_eq!(presence().expires_at(1_000.0), 1_120.0);
    }

    #[test]
    fn renewal_comes_round_well_before_the_record_expires() {
        let renewals_before_expiry = presence().as_seconds() / RENEWAL_SECONDS;
        assert!(renewals_before_expiry >= 2);
    }

    #[test]
    fn ringing_and_scheduling_keep_their_own_lifetimes() {
        assert_eq!(ring().as_seconds(), 30);
        assert_eq!(schedule().as_seconds(), 2_592_000);
    }

    #[test]
    fn a_lifetime_of_zero_seconds_does_not_exist() {
        assert!(Lifetime::seconds(0).is_none());
        assert_eq!(Lifetime::seconds(1).unwrap().as_seconds(), 1);
    }
}
