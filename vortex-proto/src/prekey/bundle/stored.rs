#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredBundle {
    pub device_id: Option<i64>,
    pub identity_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_sig: Vec<u8>,
    pub signed_prekey_id: i64,
    pub identity_key_ed: Option<Vec<u8>>,
    pub identity_key_sig: Option<Vec<u8>>,
    pub supports_v2: Option<bool>,
    pub device_x3dh_pub: Option<Vec<u8>>,
    pub device_sign_pub: Option<Vec<u8>>,
    pub device_cert_sig: Option<Vec<u8>>,
    pub client_device_id: Option<String>,
    pub device_kyber_pub: Option<Vec<u8>>,
    pub device_kyber_sig: Option<Vec<u8>>,
    pub device_kyber_id: Option<i64>,
}
