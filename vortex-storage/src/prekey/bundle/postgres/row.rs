use time::PrimitiveDateTime;
use vortex_proto::prekey::bundle::stored::StoredBundle;

use crate::prekey::bundle::record::BundleRecord;
use crate::time::stamp::Stamp;

pub struct BundleRow {
    pub id: i32,
    pub user_id: i32,
    pub device_id: Option<i32>,
    pub identity_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_sig: Vec<u8>,
    pub signed_prekey_id: i32,
    pub identity_key_ed: Option<Vec<u8>>,
    pub identity_key_sig: Option<Vec<u8>>,
    pub supports_v2: Option<bool>,
    pub device_x3dh_pub: Option<Vec<u8>>,
    pub device_sign_pub: Option<Vec<u8>>,
    pub device_cert_sig: Option<Vec<u8>>,
    pub client_device_id: Option<String>,
    pub device_kyber_pub: Option<Vec<u8>>,
    pub device_kyber_sig: Option<Vec<u8>>,
    pub device_kyber_id: Option<i32>,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
}

impl BundleRow {
    pub fn into_record(self) -> BundleRecord {
        BundleRecord {
            id: i64::from(self.id),
            user_id: i64::from(self.user_id),
            bundle: StoredBundle {
                device_id: self.device_id.map(i64::from),
                identity_key: self.identity_key,
                signed_prekey: self.signed_prekey,
                signed_prekey_sig: self.signed_prekey_sig,
                signed_prekey_id: i64::from(self.signed_prekey_id),
                identity_key_ed: self.identity_key_ed,
                identity_key_sig: self.identity_key_sig,
                supports_v2: self.supports_v2,
                device_x3dh_pub: self.device_x3dh_pub,
                device_sign_pub: self.device_sign_pub,
                device_cert_sig: self.device_cert_sig,
                client_device_id: self.client_device_id,
                device_kyber_pub: self.device_kyber_pub,
                device_kyber_sig: self.device_kyber_sig,
                device_kyber_id: self.device_kyber_id.map(i64::from),
            },
            created_at: Stamp::from_reading(self.created_at),
            updated_at: Stamp::from_reading(self.updated_at),
        }
    }
}
