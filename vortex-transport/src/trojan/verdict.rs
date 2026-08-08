use crate::trojan::request::incoming::Incoming;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted(Incoming),
    Unauthorized,
    NeedMore,
    Malformed,
}

impl Verdict {
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

    pub fn accepted(self) -> Option<Incoming> {
        match self {
            Verdict::Accepted(incoming) => Some(incoming),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Verdict;
    use crate::trojan::request::header::Header;
    use crate::trojan::request::incoming::Incoming;
    use crate::trojan::secret::password_hash::PasswordHash;

    fn accepted() -> Verdict {
        Verdict::Accepted(Incoming::new(
            PasswordHash::derive(b"testpass").unwrap(),
            Header::connect("13.10.1.2", 443).unwrap(),
            Vec::new(),
        ))
    }

    #[test]
    fn only_an_accepted_verdict_carries_a_request() {
        assert!(accepted().is_accepted());
        assert!(accepted().accepted().is_some());
        assert_eq!(Verdict::Unauthorized.accepted(), None);
        assert_eq!(Verdict::Malformed.accepted(), None);
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
}
