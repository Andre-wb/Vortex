use serde::Deserialize;

use crate::prekey::publish::one_time::OneTimeUpload;
use crate::prekey::publish::one_time_kyber::OneTimeKyberUpload;

#[derive(Debug, Clone, Deserialize)]
pub struct PublishRequest {
    pub identity_key: String,
    pub signed_prekey: String,
    pub signed_prekey_sig: String,
    pub signed_prekey_id: i64,
    #[serde(default)]
    pub identity_key_ed: Option<String>,
    #[serde(default)]
    pub identity_key_sig: Option<String>,
    #[serde(default)]
    pub supports_v2: Option<bool>,
    #[serde(default)]
    pub device_x3dh_pub: Option<String>,
    #[serde(default)]
    pub device_sign_pub: Option<String>,
    #[serde(default)]
    pub device_cert_sig: Option<String>,
    #[serde(default)]
    pub device_kyber_pub: Option<String>,
    #[serde(default)]
    pub device_kyber_sig: Option<String>,
    #[serde(default)]
    pub device_kyber_id: Option<i64>,
    #[serde(default)]
    pub one_time_prekeys: Vec<OneTimeUpload>,
    #[serde(default)]
    pub one_time_kyber_prekeys: Vec<OneTimeKyberUpload>,
}

impl PublishRequest {
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::PublishRequest;

    #[test]
    fn the_smallest_accepted_payload_carries_only_the_account_bundle() {
        let request = PublishRequest::from_json(
            r#"{"identity_key":"00","signed_prekey":"01","signed_prekey_sig":"02","signed_prekey_id":7}"#,
        )
        .unwrap();
        assert_eq!(request.signed_prekey_id, 7);
        assert!(request.identity_key_ed.is_none());
        assert!(request.one_time_prekeys.is_empty());
        assert!(request.one_time_kyber_prekeys.is_empty());
    }

    #[test]
    fn a_payload_without_the_account_bundle_is_not_a_publish() {
        assert!(PublishRequest::from_json(r#"{"identity_key":"00"}"#).is_err());
    }

    #[test]
    fn explicit_nulls_read_the_same_as_absent_fields() {
        let request = PublishRequest::from_json(
            r#"{"identity_key":"00","signed_prekey":"01","signed_prekey_sig":"02","signed_prekey_id":0,
                "identity_key_ed":null,"supports_v2":null,"device_kyber_id":null}"#,
        )
        .unwrap();
        assert!(request.identity_key_ed.is_none());
        assert!(request.supports_v2.is_none());
        assert!(request.device_kyber_id.is_none());
    }
}
