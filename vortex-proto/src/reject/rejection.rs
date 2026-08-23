pub const STATUS_BAD_REQUEST: u16 = 400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub status: u16,
    pub detail: String,
}

impl Rejection {
    pub fn bad_request(detail: &str) -> Self {
        Rejection {
            status: STATUS_BAD_REQUEST,
            detail: detail.to_string(),
        }
    }

    pub fn key_hex() -> Self {
        Rejection::bad_request("Invalid hex encoding in keys")
    }

    pub fn key_lengths() -> Self {
        Rejection::bad_request("Invalid key lengths")
    }

    pub fn identity_hex() -> Self {
        Rejection::bad_request("Invalid hex encoding in identity key/signature")
    }

    pub fn identity_lengths() -> Self {
        Rejection::bad_request("Invalid identity key/signature lengths")
    }

    pub fn device_hex() -> Self {
        Rejection::bad_request("Invalid hex encoding in device-identity fields")
    }

    pub fn device_lengths() -> Self {
        Rejection::bad_request("Invalid device-identity field lengths")
    }

    pub fn kyber_hex() -> Self {
        Rejection::bad_request("Invalid hex encoding in Kyber pre-key fields")
    }

    pub fn kyber_lengths() -> Self {
        Rejection::bad_request("Invalid Kyber pre-key field lengths")
    }

    pub fn unusable_identity_key() -> Self {
        Rejection::bad_request("Unusable Ed25519 identity key")
    }

    pub fn unusable_device_key() -> Self {
        Rejection::bad_request("Unusable device signing key")
    }

    pub fn signed_prekey_id() -> Self {
        Rejection::bad_request("Invalid signed_prekey_id")
    }

    pub fn kyber_prekey_id() -> Self {
        Rejection::bad_request("Invalid device_kyber_id")
    }

    pub fn one_time_hex(key_id: i64) -> Self {
        Rejection::bad_request(&format!(
            "Invalid hex encoding in one-time pre-key, key_id={key_id}"
        ))
    }

    pub fn one_time_length(key_id: i64) -> Self {
        Rejection::bad_request(&format!("Invalid one-time pre-key length, key_id={key_id}"))
    }

    pub fn kyber_one_time_hex(key_id: i64) -> Self {
        Rejection::bad_request(&format!(
            "Invalid hex encoding in one-time Kyber pre-key, key_id={key_id}"
        ))
    }

    pub fn kyber_one_time_length(key_id: i64) -> Self {
        Rejection::bad_request(&format!(
            "Invalid one-time Kyber pre-key length, key_id={key_id}"
        ))
    }

    pub fn one_time_batch(maximum: usize) -> Self {
        Rejection::bad_request(&format!("At most {maximum} one-time pre-keys per publish"))
    }

    pub fn kyber_batch(maximum: usize) -> Self {
        Rejection::bad_request(&format!(
            "At most {maximum} one-time Kyber pre-keys per publish"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{Rejection, STATUS_BAD_REQUEST};

    #[test]
    fn every_format_rejection_is_a_bad_request() {
        for rejection in [
            Rejection::key_hex(),
            Rejection::key_lengths(),
            Rejection::identity_hex(),
            Rejection::identity_lengths(),
            Rejection::device_hex(),
            Rejection::device_lengths(),
            Rejection::kyber_hex(),
            Rejection::kyber_lengths(),
            Rejection::unusable_identity_key(),
            Rejection::unusable_device_key(),
            Rejection::signed_prekey_id(),
            Rejection::kyber_prekey_id(),
            Rejection::one_time_batch(100),
            Rejection::kyber_batch(100),
            Rejection::one_time_hex(1),
            Rejection::one_time_length(1),
            Rejection::kyber_one_time_hex(1),
            Rejection::kyber_one_time_length(1),
        ] {
            assert_eq!(rejection.status, STATUS_BAD_REQUEST);
            assert!(!rejection.detail.is_empty());
        }
    }

    #[test]
    fn the_batch_limit_is_named_in_the_detail() {
        assert_eq!(
            Rejection::one_time_batch(100).detail,
            "At most 100 one-time pre-keys per publish"
        );
    }

    #[test]
    fn a_refused_one_time_key_is_named_by_its_own_identifier() {
        assert_eq!(
            Rejection::one_time_hex(7).detail,
            "Invalid hex encoding in one-time pre-key, key_id=7"
        );
        assert_eq!(
            Rejection::kyber_one_time_length(7).detail,
            "Invalid one-time Kyber pre-key length, key_id=7"
        );
    }
}
