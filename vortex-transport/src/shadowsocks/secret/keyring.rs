use crate::shadowsocks::secret::password_key::PasswordKey;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keyring {
    current: Option<PasswordKey>,
    previous: Option<PasswordKey>,
    extra: Vec<PasswordKey>,
}

impl Keyring {
    pub fn new(password: &[u8], previous: &[u8]) -> Self {
        Keyring {
            current: PasswordKey::derive(password),
            previous: PasswordKey::derive(previous),
            extra: Vec::new(),
        }
    }

    pub fn reload(&mut self, password: &[u8], previous: &[u8]) {
        self.current = PasswordKey::derive(password);
        self.previous = PasswordKey::derive(previous);
    }

    pub fn add(&mut self, password: &[u8]) -> bool {
        let Some(key) = PasswordKey::derive(password) else {
            return false;
        };
        if self.extra.contains(&key) {
            return false;
        }
        self.extra.push(key);
        true
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

    pub fn accepted(&self) -> impl Iterator<Item = &PasswordKey> {
        self.current
            .iter()
            .chain(self.previous.iter())
            .chain(self.extra.iter())
    }

    pub fn accepted_count(&self) -> usize {
        self.accepted().count()
    }
}

#[cfg(test)]
mod tests {
    use super::Keyring;
    use crate::shadowsocks::secret::password_key::PasswordKey;

    fn key(password: &[u8]) -> PasswordKey {
        PasswordKey::derive(password).unwrap()
    }

    #[test]
    fn an_empty_password_leaves_the_keyring_unconfigured() {
        let keyring = Keyring::new(b"", b"");
        assert!(!keyring.is_configured());
        assert_eq!(keyring.accepted_count(), 0);
        assert!(!keyring.accepts_previous());
        assert_eq!(keyring.sealing_key(), None);
    }

    #[test]
    fn the_previous_password_is_accepted_but_never_used_for_sealing() {
        let keyring = Keyring::new(b"new", b"old");
        assert!(keyring.accepts_previous());
        assert_eq!(keyring.sealing_key(), Some(&key(b"new")));
        assert!(keyring.accepted().any(|known| known == &key(b"old")));
    }

    #[test]
    fn an_extra_password_survives_a_rotation() {
        let mut keyring = Keyring::new(b"new", b"old");
        assert!(keyring.add(b"extra"));
        keyring.reload(b"newer", b"new");
        assert!(keyring.accepted().any(|known| known == &key(b"extra")));
        assert!(!keyring.accepted().any(|known| known == &key(b"old")));
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
    fn the_current_password_is_the_first_one_tried() {
        let mut keyring = Keyring::new(b"new", b"old");
        keyring.add(b"extra");
        let order: Vec<PasswordKey> = keyring.accepted().copied().collect();
        assert_eq!(order, vec![key(b"new"), key(b"old"), key(b"extra")]);
    }

    #[test]
    fn a_key_never_writes_itself_into_a_log() {
        let keyring = Keyring::new(b"new", b"");
        let shown = format!("{keyring:?}");
        assert!(
            !shown.contains("73"),
            "ключ попал в отладочный вывод: {shown}"
        );
    }
}
