use serde::Serialize;

use crate::prekey::bundle::device_bundle::DeviceBundle;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleList {
    pub user_id: i64,
    pub bundles: Vec<DeviceBundle>,
}
