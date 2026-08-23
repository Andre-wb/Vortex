use crate::account::user_id::UserId;
use crate::challenge::id::ChallengeId;
use crate::qr::state::State;
use crate::qr::wire::WireRefusal;

pub const PENDING: &str = "p";
pub const CONFIRMED: &str = "c";
const SEPARATOR: char = ':';

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrSession {
    challenge: ChallengeId,
    state: State,
}

impl QrSession {
    pub fn pending(challenge: ChallengeId) -> Self {
        QrSession {
            challenge,
            state: State::Pending,
        }
    }

    pub fn confirmed_by(&self, user: UserId) -> Self {
        QrSession {
            challenge: self.challenge.clone(),
            state: State::Confirmed(user),
        }
    }

    pub fn challenge(&self) -> &ChallengeId {
        &self.challenge
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn to_wire(&self) -> String {
        match self.state {
            State::Pending => format!("{PENDING}{SEPARATOR}{}", self.challenge.as_str()),
            State::Confirmed(user) => format!(
                "{CONFIRMED}{SEPARATOR}{}{SEPARATOR}{}",
                self.challenge.as_str(),
                user.value()
            ),
        }
    }

    pub fn parse(wire: &str) -> Result<Self, WireRefusal> {
        let mut parts = wire.split(SEPARATOR);
        let kind = parts.next().ok_or(WireRefusal::Malformed)?;
        let challenge = ChallengeId::parse(parts.next().ok_or(WireRefusal::Malformed)?)
            .map_err(|_| WireRefusal::UnknownChallenge)?;
        let session = match kind {
            PENDING => QrSession::pending(challenge),
            CONFIRMED => {
                let account = parts.next().ok_or(WireRefusal::Malformed)?;
                let user = account
                    .parse::<i64>()
                    .ok()
                    .and_then(UserId::of)
                    .ok_or(WireRefusal::UnknownAccount)?;
                QrSession::pending(challenge).confirmed_by(user)
            }
            _ => return Err(WireRefusal::Malformed),
        };
        if parts.next().is_some() {
            return Err(WireRefusal::Malformed);
        }
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::QrSession;
    use crate::account::user_id::UserId;
    use crate::challenge::id::ChallengeId;
    use crate::qr::state::State;
    use crate::qr::wire::WireRefusal;

    fn challenge() -> ChallengeId {
        ChallengeId::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    fn a_pending_session_survives_the_trip_through_the_store() {
        let session = QrSession::pending(challenge());
        assert_eq!(QrSession::parse(&session.to_wire()).unwrap(), session);
        assert_eq!(session.state(), State::Pending);
    }

    #[test]
    fn a_confirmed_session_carries_the_account_across_the_store() {
        let session = QrSession::pending(challenge()).confirmed_by(UserId::of(7).unwrap());
        let back = QrSession::parse(&session.to_wire()).unwrap();
        assert_eq!(back, session);
        assert_eq!(back.state().confirmed_by(), Some(UserId::of(7).unwrap()));
        assert_eq!(back.challenge(), &challenge());
    }

    #[test]
    fn confirming_keeps_the_challenge_the_session_was_opened_with() {
        let pending = QrSession::pending(challenge());
        assert_eq!(
            pending.confirmed_by(UserId::of(7).unwrap()).challenge(),
            &challenge()
        );
    }

    #[test]
    fn what_the_store_could_not_have_written_is_refused() {
        assert_eq!(QrSession::parse("").unwrap_err(), WireRefusal::Malformed);
        assert_eq!(
            QrSession::parse("x:aaaa").unwrap_err(),
            WireRefusal::Malformed
        );
        assert_eq!(
            QrSession::parse("c:aaaa").unwrap_err(),
            WireRefusal::Malformed
        );
        assert_eq!(
            QrSession::parse("p:aaaa:bb").unwrap_err(),
            WireRefusal::Malformed
        );
        assert_eq!(
            QrSession::parse("c:aaaa:0").unwrap_err(),
            WireRefusal::UnknownAccount
        );
        assert_eq!(
            QrSession::parse("p:aa bb").unwrap_err(),
            WireRefusal::UnknownChallenge
        );
    }
}
