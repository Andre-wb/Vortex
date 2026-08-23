use crate::account::user_id::UserId;
use crate::challenge::secret::ChallengeSecret;
use crate::login::binding::Binding;
use crate::login::key::LoginPublicKey;
use crate::login::wire::WireRefusal;
use crate::qr::session_id::QrSessionId;

const ACCOUNT: &str = "a";
const QR: &str = "q";
const DECOY: &str = "d";
const SEPARATOR: char = ':';

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginChallenge {
    secret: ChallengeSecret,
    binding: Binding,
}

impl LoginChallenge {
    pub fn new(secret: ChallengeSecret, binding: Binding) -> Self {
        LoginChallenge { secret, binding }
    }

    pub fn secret(&self) -> &ChallengeSecret {
        &self.secret
    }

    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    pub fn to_wire(&self) -> String {
        let secret = self.secret.to_hex();
        match &self.binding {
            Binding::Account { user, pubkey } => format!(
                "{ACCOUNT}{SEPARATOR}{}{SEPARATOR}{}{SEPARATOR}{secret}",
                user.value(),
                pubkey.as_str()
            ),
            Binding::QrSession(session) => {
                format!("{QR}{SEPARATOR}{}{SEPARATOR}{secret}", session.as_str())
            }
            Binding::Decoy => format!("{DECOY}{SEPARATOR}{secret}"),
        }
    }

    pub fn parse(wire: &str) -> Result<Self, WireRefusal> {
        let mut parts = wire.split(SEPARATOR);
        let kind = parts.next().ok_or(WireRefusal::Malformed)?;
        let record = match kind {
            ACCOUNT => {
                let account = parts.next().ok_or(WireRefusal::Malformed)?;
                let pubkey = parts.next().ok_or(WireRefusal::Malformed)?;
                let secret = parts.next().ok_or(WireRefusal::Malformed)?;
                LoginChallenge::new(
                    ChallengeSecret::parse_hex(secret).map_err(WireRefusal::Secret)?,
                    Binding::Account {
                        user: account
                            .parse::<i64>()
                            .ok()
                            .and_then(UserId::of)
                            .ok_or(WireRefusal::UnknownAccount)?,
                        pubkey: LoginPublicKey::parse(pubkey).map_err(WireRefusal::Key)?,
                    },
                )
            }
            QR => {
                let session = parts.next().ok_or(WireRefusal::Malformed)?;
                let secret = parts.next().ok_or(WireRefusal::Malformed)?;
                LoginChallenge::new(
                    ChallengeSecret::parse_hex(secret).map_err(WireRefusal::Secret)?,
                    Binding::QrSession(
                        QrSessionId::parse(session).map_err(|_| WireRefusal::UnknownSession)?,
                    ),
                )
            }
            DECOY => {
                let secret = parts.next().ok_or(WireRefusal::Malformed)?;
                LoginChallenge::new(
                    ChallengeSecret::parse_hex(secret).map_err(WireRefusal::Secret)?,
                    Binding::Decoy,
                )
            }
            _ => return Err(WireRefusal::Malformed),
        };
        if parts.next().is_some() {
            return Err(WireRefusal::Malformed);
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::LoginChallenge;
    use crate::account::user_id::UserId;
    use crate::challenge::secret::ChallengeSecret;
    use crate::login::binding::Binding;
    use crate::login::key::LoginPublicKey;
    use crate::login::wire::WireRefusal;
    use crate::qr::session_id::QrSessionId;
    use crate::random::fixed_entropy::FixedEntropy;

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn secret() -> ChallengeSecret {
        ChallengeSecret::draw(&FixedEntropy::counting_from(0))
    }

    fn round_trip(binding: Binding) {
        let record = LoginChallenge::new(secret(), binding);
        assert_eq!(LoginChallenge::parse(&record.to_wire()).unwrap(), record);
    }

    #[test]
    fn a_challenge_bound_to_an_account_survives_the_trip_through_the_store() {
        round_trip(Binding::Account {
            user: UserId::of(7).unwrap(),
            pubkey: LoginPublicKey::parse(KEY).unwrap(),
        });
    }

    #[test]
    fn a_challenge_bound_to_a_qr_session_survives_the_trip_through_the_store() {
        round_trip(Binding::QrSession(QrSessionId::parse("abcd").unwrap()));
    }

    #[test]
    fn a_decoy_survives_the_trip_through_the_store() {
        round_trip(Binding::Decoy);
    }

    #[test]
    fn what_the_store_could_not_have_written_is_refused() {
        assert_eq!(
            LoginChallenge::parse("").unwrap_err(),
            WireRefusal::Malformed
        );
        assert_eq!(
            LoginChallenge::parse("x:aa").unwrap_err(),
            WireRefusal::Malformed
        );
        assert_eq!(
            LoginChallenge::parse("d").unwrap_err(),
            WireRefusal::Malformed
        );
        assert_eq!(
            LoginChallenge::parse(&format!("a:0:{KEY}:{}", secret().to_hex())).unwrap_err(),
            WireRefusal::UnknownAccount
        );
        assert!(matches!(
            LoginChallenge::parse(&format!("a:7:short:{}", secret().to_hex())).unwrap_err(),
            WireRefusal::Key(_)
        ));
    }

    #[test]
    fn a_record_with_more_fields_than_written_is_refused() {
        let record = LoginChallenge::new(secret(), Binding::Decoy);
        assert_eq!(
            LoginChallenge::parse(&format!("{}:extra", record.to_wire())).unwrap_err(),
            WireRefusal::Malformed
        );
    }
}
