use crate::challenge::id::ChallengeId;
use crate::challenge::secret::ChallengeSecret;
use crate::qr::session_id::QrSessionId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedSession {
    session: QrSessionId,
    challenge: ChallengeId,
    secret: ChallengeSecret,
    expires_in: u64,
}

impl OpenedSession {
    pub fn new(
        session: QrSessionId,
        challenge: ChallengeId,
        secret: ChallengeSecret,
        expires_in: u64,
    ) -> Self {
        OpenedSession {
            session,
            challenge,
            secret,
            expires_in,
        }
    }

    pub fn session(&self) -> &QrSessionId {
        &self.session
    }

    pub fn challenge(&self) -> &ChallengeId {
        &self.challenge
    }

    pub fn secret(&self) -> &ChallengeSecret {
        &self.secret
    }

    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }
}

#[cfg(test)]
mod tests {
    use super::OpenedSession;
    use crate::challenge::id::ChallengeId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::qr::session_id::QrSessionId;
    use crate::random::fixed_entropy::FixedEntropy;

    #[test]
    fn the_desktop_is_handed_everything_the_qr_code_must_carry() {
        let source = FixedEntropy::counting_from(0);
        let opened = OpenedSession::new(
            QrSessionId::draw(&source),
            ChallengeId::draw(&source),
            ChallengeSecret::draw(&source),
            300,
        );
        assert_eq!(opened.session().as_str().len(), 48);
        assert_eq!(opened.challenge().as_str().len(), 32);
        assert_eq!(opened.secret().to_hex().len(), 64);
        assert_eq!(opened.expires_in(), 300);
    }
}
