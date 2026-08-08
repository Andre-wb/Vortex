use crate::shadowtls::secret::keyring::Keyring;
use crate::shadowtls::secret::password_key::PasswordKey;
use crate::shadowtls::switch::sealer::SWITCH_PREFIX_LEN;
use crate::shadowtls::switch::session_id::{SessionId, SESSION_ID_LEN};
use crate::shadowtls::switch::token;
use crate::tls::record::header::CONTENT_APPLICATION_DATA;
use crate::tls::server_hello::ServerRandom;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    pub session_id: SessionId,
    pub key: PasswordKey,
}

pub fn match_record(
    keyring: &Keyring,
    server_random: Option<&ServerRandom>,
    content_type: u8,
    payload: &[u8],
) -> Option<Accepted> {
    if content_type != CONTENT_APPLICATION_DATA || payload.len() < SWITCH_PREFIX_LEN {
        return None;
    }
    let server_random = server_random?;
    let session_id = SessionId::parse(&payload[..SESSION_ID_LEN])?;
    let candidate = &payload[SESSION_ID_LEN..SWITCH_PREFIX_LEN];

    keyring
        .accepted_keys()
        .find(|key| token::verify(key, server_random, &session_id, candidate))
        .map(|key| Accepted {
            session_id,
            key: *key,
        })
}

#[cfg(test)]
mod tests {
    use super::match_record;
    use crate::shadowtls::secret::keyring::Keyring;
    use crate::shadowtls::secret::password_key;
    use crate::shadowtls::switch::sealer::payload;
    use crate::shadowtls::switch::session_id::SessionId;

    fn session_id() -> SessionId {
        SessionId::from_bytes([0x02; 16])
    }

    fn body(password: &[u8], server_random: &[u8; 32], padding: &[u8]) -> Vec<u8> {
        let key = password_key::derive(password).unwrap();
        payload(&key, server_random, &session_id(), padding)
    }

    #[test]
    fn a_record_sealed_with_the_current_password_matches() {
        let keyring = Keyring::new(b"testpass", b"");
        let found = match_record(
            &keyring,
            Some(&[0x01; 32]),
            0x17,
            &body(b"testpass", &[0x01; 32], b""),
        );
        assert_eq!(found.unwrap().session_id, session_id());
    }

    #[test]
    fn a_record_sealed_with_the_previous_password_still_matches() {
        let keyring = Keyring::new(b"new", b"old");
        let found = match_record(
            &keyring,
            Some(&[0x01; 32]),
            0x17,
            &body(b"old", &[0x01; 32], b""),
        );
        assert_eq!(
            found.unwrap().key,
            password_key::derive(b"old").unwrap(),
            "ключи сессии обязаны выводиться из того же пароля, что принял маркер"
        );
    }

    #[test]
    fn padding_after_the_marker_is_ignored() {
        let keyring = Keyring::new(b"testpass", b"");
        let padded = body(b"testpass", &[0x01; 32], &[0x00; 200]);
        assert!(match_record(&keyring, Some(&[0x01; 32]), 0x17, &padded).is_some());
    }

    #[test]
    fn nothing_matches_before_the_donor_random_is_known() {
        let keyring = Keyring::new(b"testpass", b"");
        assert!(match_record(&keyring, None, 0x17, &body(b"testpass", &[0x01; 32], b"")).is_none());
    }

    #[test]
    fn a_marker_from_another_connection_does_not_match() {
        let keyring = Keyring::new(b"testpass", b"");
        let captured = body(b"testpass", &[0x01; 32], b"");
        assert!(match_record(&keyring, Some(&[0xAA; 32]), 0x17, &captured).is_none());
    }

    #[test]
    fn only_application_data_can_carry_a_switch() {
        let keyring = Keyring::new(b"testpass", b"");
        let good = body(b"testpass", &[0x01; 32], b"");
        for content_type in [0x14u8, 0x15, 0x16] {
            assert!(match_record(&keyring, Some(&[0x01; 32]), content_type, &good).is_none());
        }
    }

    #[test]
    fn a_short_or_forged_payload_does_not_match() {
        let keyring = Keyring::new(b"testpass", b"");
        let good = body(b"testpass", &[0x01; 32], b"");
        assert!(match_record(&keyring, Some(&[0x01; 32]), 0x17, &good[..23]).is_none());
        assert!(match_record(&keyring, Some(&[0x01; 32]), 0x17, &[0x00; 24]).is_none());
    }

    #[test]
    fn an_unconfigured_keyring_accepts_nothing() {
        let keyring = Keyring::new(b"", b"");
        let good = body(b"testpass", &[0x01; 32], b"");
        assert!(match_record(&keyring, Some(&[0x01; 32]), 0x17, &good).is_none());
    }
}
