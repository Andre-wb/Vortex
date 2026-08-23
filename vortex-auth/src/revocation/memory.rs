use std::collections::HashMap;

use parking_lot::RwLock;

use crate::error::Result;
use crate::ports::denylist::Denylist;
use crate::token::jti::Jti;
use crate::token::ttl::Ttl;

pub struct MemoryDenylist {
    revoked: RwLock<HashMap<String, f64>>,
}

impl Default for MemoryDenylist {
    fn default() -> Self {
        MemoryDenylist::new()
    }
}

impl MemoryDenylist {
    pub fn new() -> Self {
        MemoryDenylist {
            revoked: RwLock::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.revoked.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Denylist for MemoryDenylist {
    fn remember(&self, jti: &Jti, ttl: Ttl, now: f64) -> Result<()> {
        let mut revoked = self.revoked.write();
        revoked.retain(|_, until| *until > now);
        revoked.insert(jti.as_str().to_owned(), now + ttl.as_seconds() as f64);
        Ok(())
    }

    fn holds(&self, jti: &Jti, now: f64) -> bool {
        match self.revoked.read().get(jti.as_str()) {
            Some(until) => *until > now,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryDenylist;
    use crate::ports::denylist::Denylist;
    use crate::token::jti::Jti;
    use crate::token::ttl::Ttl;

    fn jti(value: &str) -> Jti {
        Jti::parse(value).unwrap()
    }

    #[test]
    fn what_was_revoked_is_held_until_the_moment_it_would_have_expired() {
        let list = MemoryDenylist::new();
        list.remember(&jti("aaaa"), Ttl::seconds(60).unwrap(), 1_000.0)
            .unwrap();
        assert!(list.holds(&jti("aaaa"), 1_059.0));
        assert!(!list.holds(&jti("aaaa"), 1_060.0));
    }

    #[test]
    fn writing_forgets_what_has_already_expired() {
        let list = MemoryDenylist::new();
        list.remember(&jti("aaaa"), Ttl::seconds(60).unwrap(), 1_000.0)
            .unwrap();
        list.remember(&jti("bbbb"), Ttl::seconds(60).unwrap(), 2_000.0)
            .unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn a_store_nobody_wrote_to_holds_nothing() {
        let list = MemoryDenylist::new();
        assert!(list.is_empty());
        assert!(!list.holds(&jti("aaaa"), 1_000.0));
    }
}
