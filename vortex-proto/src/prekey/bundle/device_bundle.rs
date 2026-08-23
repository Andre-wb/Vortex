use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceBundle {
    pub device_id: Option<i64>,
    pub identity_key: String,
    pub signed_prekey: String,
    pub signed_prekey_sig: String,
    pub signed_prekey_id: i64,
    pub identity_key_ed: Option<String>,
    pub identity_key_sig: Option<String>,
    pub supports_v2: Option<bool>,
    pub device_x3dh_pub: Option<String>,
    pub device_sign_pub: Option<String>,
    pub device_cert_sig: Option<String>,
    pub client_device_id: Option<String>,
    pub device_kyber_pub: Option<String>,
    pub device_kyber_sig: Option<String>,
    pub device_kyber_id: Option<i64>,
    pub one_time_prekey: Option<String>,
    pub one_time_prekey_id: Option<i64>,
}
