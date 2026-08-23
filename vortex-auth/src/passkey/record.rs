use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;
use crate::passkey::purpose::Purpose;
use crate::passkey::wire::WireRefusal;

const REGISTRATION: char = 'r';
const LOGIN: char = 'l';
const SEPARATOR: char = ':';

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyChallenge {
    secret: ChallengeSecret,
    purpose: Purpose,
}

impl PasskeyChallenge {
    pub fn new(secret: ChallengeSecret, purpose: Purpose) -> Self {
        PasskeyChallenge { secret, purpose }
    }

    pub fn secret(&self) -> &ChallengeSecret {
        &self.secret
    }

    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    pub fn to_wire(&self) -> String {
        match self.purpose {
            Purpose::Registration(user) => {
                format!(
                    "{REGISTRATION}{SEPARATOR}{}{SEPARATOR}{}",
                    user.value(),
                    self.secret.to_hex()
                )
            }
            Purpose::Login => format!("{LOGIN}{SEPARATOR}{}", self.secret.to_hex()),
        }
    }

    pub fn parse(wire: &str) -> Result<Self, WireRefusal> {
        let mut parts = wire.split(SEPARATOR);
        let kind = parts.next().ok_or(WireRefusal::Malformed)?;
        match kind {
            "r" => {
                let account = parts.next().ok_or(WireRefusal::Malformed)?;
                let secret = parts.next().ok_or(WireRefusal::Malformed)?;
                if parts.next().is_some() {
                    return Err(WireRefusal::Malformed);
                }
                let user = account
                    .parse::<i64>()
                    .ok()
                    .and_then(UserId::of)
                    .ok_or(WireRefusal::UnknownAccount)?;
                Ok(PasskeyChallenge::new(
                    ChallengeSecret::parse_hex(secret).map_err(WireRefusal::Secret)?,
                    Purpose::Registration(user),
                ))
            }
            "l" => {
                let secret = parts.next().ok_or(WireRefusal::Malformed)?;
                if parts.next().is_some() {
                    return Err(WireRefusal::Malformed);
                }
                Ok(PasskeyChallenge::new(
                    ChallengeSecret::parse_hex(secret).map_err(WireRefusal::Secret)?,
                    Purpose::Login,
                ))
            }
            _ => Err(WireRefusal::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PasskeyChallenge;
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::passkey::purpose::Purpose;
    use crate::passkey::wire::WireRefusal;
    use crate::random::fixed_entropy::FixedEntropy;

    fn secret() -> ChallengeSecret {
        ChallengeSecret::draw(&FixedEntropy::counting_from(0))
    }

    #[test]
    fn a_registration_challenge_survives_the_trip_through_the_store() {
        let record = PasskeyChallenge::new(secret(), Purpose::Registration(UserId::of(7).unwrap()));
        assert_eq!(PasskeyChallenge::parse(&record.to_wire()).unwrap(), record);
    }

    #[test]
    fn a_login_challenge_survives_the_trip_through_the_store() {
        let record = PasskeyChallenge::new(secret(), Purpose::Login);
        assert_eq!(PasskeyChallenge::parse(&record.to_wire()).unwrap(), record);
    }

    #[test]
    fn a_login_challenge_never_reads_back_as_a_registration_one() {
        let login = PasskeyChallenge::new(secret(), Purpose::Login);
        let parsed = PasskeyChallenge::parse(&login.to_wire()).unwrap();
        assert_eq!(parsed.purpose(), Purpose::Login);
        assert_eq!(parsed.purpose().owner(), None);
    }

    #[test]
    fn what_the_store_could_not_have_written_is_refused() {
        assert_eq!(
            PasskeyChallenge::parse("").unwrap_err(),
            WireRefusal::Malformed
        );
        assert_eq!(
            PasskeyChallenge::parse("x:aa").unwrap_err(),
            WireRefusal::Malformed
        );
        assert_eq!(
            PasskeyChallenge::parse("l").unwrap_err(),
            WireRefusal::Malformed
        );
        assert_eq!(
            PasskeyChallenge::parse("r:0:00112233445566778899aabbccddeeff").unwrap_err(),
            WireRefusal::UnknownAccount
        );
        assert!(matches!(
            PasskeyChallenge::parse("l:zz").unwrap_err(),
            WireRefusal::Secret(_)
        ));
    }
}
