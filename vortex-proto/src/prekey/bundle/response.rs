use serde::Serialize;

use crate::prekey::bundle::device_bundle::DeviceBundle;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleResponse {
    pub user_id: i64,
    #[serde(flatten)]
    pub bundle: DeviceBundle,
}
