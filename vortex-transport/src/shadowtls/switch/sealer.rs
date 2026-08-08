use crate::ports::random_source::RandomSource;
use crate::shadowtls::config::ShadowTlsConfig;
use crate::shadowtls::secret::password_key::PasswordKey;
use crate::shadowtls::switch::session_id::{SessionId, SESSION_ID_LEN};
use crate::shadowtls::switch::token::{self, SWITCH_TOKEN_LEN};
use crate::tls::record::header::{self, CONTENT_APPLICATION_DATA};
use crate::tls::server_hello::ServerRandom;

pub const SWITCH_PREFIX_LEN: usize = SESSION_ID_LEN + SWITCH_TOKEN_LEN;

pub fn payload(
    key: &PasswordKey,
    server_random: &ServerRandom,
    session_id: &SessionId,
    padding: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SWITCH_PREFIX_LEN + padding.len());
    out.extend_from_slice(session_id.as_bytes());
    out.extend_from_slice(&token::derive(key, server_random, session_id));
    out.extend_from_slice(padding);
    out
}

pub fn seal(
    key: &PasswordKey,
    server_random: &ServerRandom,
    session_id: &SessionId,
    config: &ShadowTlsConfig,
    random: &dyn RandomSource,
) -> Option<Vec<u8>> {
    let padding = random.bytes(config.padding_len(random));
    into_record(payload(key, server_random, session_id, &padding))
}

pub fn into_record(body: Vec<u8>) -> Option<Vec<u8>> {
    let mut record = header::encode(CONTENT_APPLICATION_DATA, body.len())?.to_vec();
    record.extend_from_slice(&body);
    Some(record)
}

#[cfg(test)]
mod tests {
    use super::{into_record, payload, seal, SWITCH_PREFIX_LEN};
    use crate::random::fixed_random::FixedRandom;
    use crate::shadowtls::config::ShadowTlsConfig;
    use crate::shadowtls::secret::password_key;
    use crate::shadowtls::switch::session_id::SessionId;
    use crate::tls::record::header;

    fn key() -> [u8; 32] {
        password_key::derive(b"testpass").unwrap()
    }

    #[test]
    fn the_record_is_application_data_with_a_matching_length() {
        let random = FixedRandom::new(vec![]).with_filler(0x00);
        let record = seal(
            &key(),
            &[0x01; 32],
            &SessionId::from_bytes([0x02; 16]),
            &ShadowTlsConfig::default(),
            &random,
        )
        .unwrap();
        let parsed = header::parse(&record).unwrap();
        assert_eq!(parsed.content_type, 0x17);
        assert_eq!(parsed.payload_len, record.len() - 5);
    }

    #[test]
    fn the_marker_is_never_sent_alone() {
        let random = FixedRandom::new(vec![]).with_filler(0x00);
        let config = ShadowTlsConfig::default();
        let record = seal(
            &key(),
            &[0x01; 32],
            &SessionId::from_bytes([0x02; 16]),
            &config,
            &random,
        )
        .unwrap();
        assert!(record.len() - 5 >= SWITCH_PREFIX_LEN + config.switch_padding_min);
    }

    #[test]
    fn the_session_id_travels_in_the_clear_in_front_of_the_marker() {
        let body = payload(&key(), &[0x01; 32], &SessionId::from_bytes([0x02; 16]), b"");
        assert_eq!(&body[..16], &[0x02u8; 16]);
        assert_eq!(body.len(), SWITCH_PREFIX_LEN);
    }

    #[test]
    fn a_body_above_the_tls_ceiling_yields_no_record() {
        assert_eq!(into_record(vec![0u8; 16_641]), None);
        assert!(into_record(vec![0u8; 16_640]).is_some());
    }

    #[test]
    fn padding_lands_after_the_marker_untouched() {
        let body = payload(
            &key(),
            &[0x01; 32],
            &SessionId::from_bytes([0x02; 16]),
            b"tail",
        );
        assert_eq!(&body[SWITCH_PREFIX_LEN..], b"tail");
    }
}
