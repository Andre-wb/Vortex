use crate::shadowtls::secret::password_key::{self, PasswordKey};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keyring {
    current: Option<PasswordKey>,
    previous: Option<PasswordKey>,
}

impl Keyring {
    pub fn new(password: &[u8], previous: &[u8]) -> Self {
        Keyring {
            current: password_key::derive(password),
            previous: password_key::derive(previous),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.current.is_some()
    }

    pub fn accepts_previous(&self) -> bool {
        self.previous.is_some()
    }

    pub fn sealing_key(&self) -> Option<&PasswordKey> {
        self.current.as_ref()
    }

    pub fn accepted_keys(&self) -> impl Iterator<Item = &PasswordKey> {
        self.current.iter().chain(self.previous.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::Keyring;

    #[test]
    fn an_empty_password_leaves_the_keyring_unconfigured() {
        let keyring = Keyring::new(b"", b"");
        assert!(!keyring.is_configured());
        assert_eq!(keyring.sealing_key(), None);
        assert_eq!(keyring.accepted_keys().count(), 0);
    }

    #[test]
    fn the_previous_password_is_accepted_but_never_used_for_sealing() {
        let keyring = Keyring::new(b"new", b"old");
        assert!(keyring.accepts_previous());
        assert_eq!(keyring.accepted_keys().count(), 2);
        assert_eq!(
            keyring.sealing_key(),
            Keyring::new(b"new", b"").sealing_key()
        );
    }

    #[test]
    fn the_current_password_is_offered_first() {
        let keyring = Keyring::new(b"new", b"old");
        let keys: Vec<_> = keyring.accepted_keys().collect();
        assert_eq!(keys[0], keyring.sealing_key().unwrap());
    }

    #[test]
    fn without_a_previous_password_only_one_key_is_accepted() {
        let keyring = Keyring::new(b"only", b"");
        assert!(!keyring.accepts_previous());
        assert_eq!(keyring.accepted_keys().count(), 1);
    }
}
