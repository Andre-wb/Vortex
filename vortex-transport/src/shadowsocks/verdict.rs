use crate::shadowsocks::accepted::Accepted;

pub enum Verdict {
    Accepted(Box<Accepted>),
    Unauthorized,
    NeedMore,
    Malformed,
}

impl Verdict {
    pub fn accept(accepted: Accepted) -> Self {
        Verdict::Accepted(Box::new(accepted))
    }

    pub fn name(&self) -> &'static str {
        match self {
            Verdict::Accepted(_) => "accepted",
            Verdict::Unauthorized => "unauthorized",
            Verdict::NeedMore => "need_more",
            Verdict::Malformed => "malformed",
        }
    }

    pub fn is_accepted(&self) -> bool {
        matches!(self, Verdict::Accepted(_))
    }

    pub fn wants_more_bytes(&self) -> bool {
        matches!(self, Verdict::NeedMore)
    }

    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Verdict::Unauthorized)
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, Verdict::Malformed)
    }

    pub fn accepted(self) -> Option<Accepted> {
        match self {
            Verdict::Accepted(accepted) => Some(*accepted),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Verdict;
    use crate::shadowsocks::accepted::Accepted;
    use crate::shadowsocks::schedule::keys;
    use crate::shadowsocks::schedule::role::Role;
    use crate::shadowsocks::schedule::salt::SessionSalt;
    use crate::shadowsocks::secret::password_key::PasswordKey;
    use crate::shadowsocks::session::Session;
    use crate::socks::destination::Destination;

    fn accepted() -> Verdict {
        let password = PasswordKey::derive(b"test_password").unwrap();
        let salt = SessionSalt::from_bytes([0x11; 32]);
        Verdict::accept(Accepted::new(
            Session::new(&keys::derive(&password, &salt, Role::Server)),
            Destination::resolve("13.10.1.2", 443).unwrap(),
            Vec::new(),
            34,
        ))
    }

    #[test]
    fn only_an_accepted_verdict_carries_a_session() {
        assert!(accepted().is_accepted());
        assert!(accepted().accepted().is_some());
        assert!(Verdict::Unauthorized.accepted().is_none());
        assert!(Verdict::Malformed.accepted().is_none());
        assert!(Verdict::NeedMore.accepted().is_none());
    }

    #[test]
    fn only_an_incomplete_verdict_asks_for_more_bytes() {
        assert!(Verdict::NeedMore.wants_more_bytes());
        assert!(!Verdict::Unauthorized.wants_more_bytes());
        assert!(!Verdict::Malformed.wants_more_bytes());
        assert!(!accepted().wants_more_bytes());
    }

    #[test]
    fn every_name_is_stable() {
        assert_eq!(accepted().name(), "accepted");
        assert_eq!(Verdict::Unauthorized.name(), "unauthorized");
        assert_eq!(Verdict::NeedMore.name(), "need_more");
        assert_eq!(Verdict::Malformed.name(), "malformed");
    }

    #[test]
    fn the_four_outcomes_never_overlap() {
        assert!(Verdict::Unauthorized.is_unauthorized());
        assert!(!Verdict::Unauthorized.is_malformed());
        assert!(Verdict::Malformed.is_malformed());
        assert!(!Verdict::Malformed.is_unauthorized());
    }
}
