use vortex_proto::prekey::bundle::stored::StoredBundle;

use crate::time::stamp::Stamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleRecord {
    pub id: i64,
    pub user_id: i64,
    pub bundle: StoredBundle,
    pub created_at: Stamp,
    pub updated_at: Stamp,
}
