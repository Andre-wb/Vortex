use std::collections::HashMap;

use parking_lot::RwLock;

use crate::account::user_id::UserId;
use crate::error::Result;
use crate::ports::password_markers::PasswordMarkers;
use crate::token::ttl::Ttl;

pub struct MemoryPasswordMarkers {
    armed: RwLock<HashMap<i64, f64>>,
}

impl Default for MemoryPasswordMarkers {
    fn default() -> Self {
        MemoryPasswordMarkers::new()
    }
}

impl MemoryPasswordMarkers {
    pub fn new() -> Self {
        MemoryPasswordMarkers {
            armed: RwLock::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.armed.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PasswordMarkers for MemoryPasswordMarkers {
    fn arm(&self, user: UserId, ttl: Ttl, now: f64) -> Result<()> {
        let mut armed = self.armed.write();
        armed.retain(|_, until| *until > now);
        armed.insert(user.value(), now + ttl.as_seconds() as f64);
        Ok(())
    }

    fn armed(&self, user: UserId, now: f64) -> bool {
        match self.armed.read().get(&user.value()) {
            Some(until) => *until > now,
            None => false,
        }
    }

    fn disarm(&self, user: UserId) -> Result<()> {
        self.armed.write().remove(&user.value());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryPasswordMarkers;
    use crate::account::user_id::UserId;
    use crate::ports::password_markers::PasswordMarkers;
    use crate::token::ttl::Ttl;

    fn user(value: i64) -> UserId {
        UserId::of(value).unwrap()
    }

    #[test]
    fn a_marker_is_armed_for_as_long_as_it_was_given() {
        let markers = MemoryPasswordMarkers::new();
        markers
            .arm(user(7), Ttl::seconds(300).unwrap(), 1_000.0)
            .unwrap();
        assert!(markers.armed(user(7), 1_299.0));
        assert!(!markers.armed(user(7), 1_300.0));
    }

    #[test]
    fn a_marker_burned_after_the_second_step_is_gone() {
        let markers = MemoryPasswordMarkers::new();
        markers
            .arm(user(7), Ttl::seconds(300).unwrap(), 1_000.0)
            .unwrap();
        markers.disarm(user(7)).unwrap();
        assert!(!markers.armed(user(7), 1_001.0));
        assert!(markers.is_empty());
    }

    #[test]
    fn one_account_never_answers_for_another() {
        let markers = MemoryPasswordMarkers::new();
        markers
            .arm(user(7), Ttl::seconds(300).unwrap(), 1_000.0)
            .unwrap();
        assert!(!markers.armed(user(8), 1_001.0));
    }
}
