use crate::trojan::secret::password_hash::PasswordHash;
use subtle::Choice;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keyring {
    current: Option<PasswordHash>,
    previous: Option<PasswordHash>,
    extra: Vec<PasswordHash>,
}

impl Keyring {
    pub fn new(password: &[u8], previous: &[u8]) -> Self {
        Keyring {
            current: PasswordHash::derive(password),
            previous: PasswordHash::derive(previous),
            extra: Vec::new(),
        }
    }

    pub fn reload(&mut self, password: &[u8], previous: &[u8]) {
        self.current = PasswordHash::derive(password);
        self.previous = PasswordHash::derive(previous);
    }

    pub fn add(&mut self, password: &[u8]) -> bool {
        let Some(hash) = PasswordHash::derive(password) else {
            return false;
        };
        if self.extra.contains(&hash) {
            return false;
        }
        self.extra.push(hash);
        true
    }

    pub fn is_configured(&self) -> bool {
        self.current.is_some()
    }

    pub fn accepts_previous(&self) -> bool {
        self.previous.is_some()
    }

    pub fn sealing_hash(&self) -> Option<&PasswordHash> {
        self.current.as_ref()
    }

    pub fn accepted(&self) -> impl Iterator<Item = &PasswordHash> {
        self.current
            .iter()
            .chain(self.previous.iter())
            .chain(self.extra.iter())
    }

    pub fn accepted_count(&self) -> usize {
        self.accepted().count()
    }

    pub fn accepts(&self, candidate: &PasswordHash) -> bool {
        let mut seen = Choice::from(0u8);
        for known in self.accepted() {
            seen |= known.ct_eq(candidate);
        }
        seen.into()
    }
}

#[cfg(test)]
mod tests {
    use super::Keyring;
    use crate::trojan::secret::password_hash::PasswordHash;

    fn hash(password: &[u8]) -> PasswordHash {
        PasswordHash::derive(password).unwrap()
    }

    #[test]
    fn an_empty_password_leaves_the_keyring_unconfigured() {
        let keyring = Keyring::new(b"", b"");
        assert!(!keyring.is_configured());
        assert_eq!(keyring.accepted_count(), 0);
        assert!(!keyring.accepts_previous());
    }

    #[test]
    fn nobody_authenticates_against_an_unconfigured_keyring() {
        let keyring = Keyring::new(b"", b"");
        assert!(!keyring.accepts(&hash(b"anything")));
        assert_eq!(keyring.sealing_hash(), None);
    }

    #[test]
    fn the_previous_password_is_accepted_but_never_used_for_sealing() {
        let keyring = Keyring::new(b"new", b"old");
        assert!(keyring.accepts_previous());
        assert!(keyring.accepts(&hash(b"old")));
        assert_eq!(keyring.sealing_hash(), Some(&hash(b"new")));
    }

    #[test]
    fn an_extra_password_survives_a_rotation() {
        let mut keyring = Keyring::new(b"new", b"old");
        assert!(keyring.add(b"extra"));
        keyring.reload(b"newer", b"new");
        assert!(keyring.accepts(&hash(b"extra")));
        assert!(!keyring.accepts(&hash(b"old")));
    }

    #[test]
    fn the_same_extra_password_is_only_kept_once() {
        let mut keyring = Keyring::new(b"new", b"");
        assert!(keyring.add(b"extra"));
        assert!(!keyring.add(b"extra"));
        assert_eq!(keyring.accepted_count(), 2);
    }

    #[test]
    fn an_empty_extra_password_is_refused() {
        let mut keyring = Keyring::new(b"new", b"");
        assert!(!keyring.add(b""));
        assert_eq!(keyring.accepted_count(), 1);
    }

    #[test]
    fn a_hash_nobody_registered_is_refused() {
        let mut keyring = Keyring::new(b"new", b"old");
        keyring.add(b"extra");
        assert!(!keyring.accepts(&hash(b"guess")));
    }
}
