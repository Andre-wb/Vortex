use serde::Serialize;

use crate::hex::encode::encode;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClaimResponse {
    pub one_time_prekey: Option<String>,
    pub one_time_prekey_id: Option<i64>,
    pub one_time_kyber_prekey: Option<String>,
    pub one_time_kyber_prekey_id: Option<i64>,
}

impl ClaimResponse {
    pub fn render(one_time: Option<(&[u8], i64)>, one_time_kyber: Option<(&[u8], i64)>) -> Self {
        ClaimResponse {
            one_time_prekey: one_time.map(|(public, _)| encode(public)),
            one_time_prekey_id: one_time.map(|(_, key_id)| key_id),
            one_time_kyber_prekey: one_time_kyber.map(|(public, _)| encode(public)),
            one_time_kyber_prekey_id: one_time_kyber.map(|(_, key_id)| key_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ClaimResponse;

    #[test]
    fn an_empty_pool_answers_with_nothing_claimed() {
        assert_eq!(ClaimResponse::render(None, None), ClaimResponse::default());
    }

    #[test]
    fn a_claimed_key_is_reported_with_its_identifier() {
        let response = ClaimResponse::render(Some((&[0x01, 0x02], 5)), None);
        assert_eq!(response.one_time_prekey, Some("0102".to_string()));
        assert_eq!(response.one_time_prekey_id, Some(5));
        assert!(response.one_time_kyber_prekey.is_none());
    }

    #[test]
    fn the_two_pools_are_reported_independently() {
        let response = ClaimResponse::render(None, Some((&[0xff], 9)));
        assert!(response.one_time_prekey.is_none());
        assert_eq!(response.one_time_kyber_prekey, Some("ff".to_string()));
        assert_eq!(response.one_time_kyber_prekey_id, Some(9));
    }
}
