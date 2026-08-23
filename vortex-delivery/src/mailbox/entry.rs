use crate::message::payload::Payload;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    stamped_at: f64,
    payload: Payload,
}

impl Entry {
    pub fn new(stamped_at: f64, payload: Payload) -> Self {
        Entry {
            stamped_at,
            payload,
        }
    }

    pub fn stamped_at(&self) -> f64 {
        self.stamped_at
    }

    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    pub fn stale(&self, now: f64, lifetime: f64) -> bool {
        now - self.stamped_at > lifetime
    }
}

#[cfg(test)]
mod tests {
    use super::Entry;
    use crate::message::payload::Payload;

    #[test]
    fn an_entry_grows_stale_only_past_its_lifetime() {
        let entry = Entry::new(100.0, Payload::of("{}"));
        assert!(!entry.stale(400.0, 300.0));
        assert!(entry.stale(400.1, 300.0));
    }
}
