use crate::hex::encode::encode;
use crate::prekey::bundle::device_bundle::DeviceBundle;
use crate::prekey::bundle::list::BundleList;
use crate::prekey::bundle::response::BundleResponse;
use crate::prekey::bundle::stored::StoredBundle;

pub fn bundle_response(user_id: i64, stored: &StoredBundle) -> BundleResponse {
    BundleResponse {
        user_id,
        bundle: device_bundle(stored),
    }
}

pub fn device_bundle(stored: &StoredBundle) -> DeviceBundle {
    DeviceBundle {
        device_id: stored.device_id,
        identity_key: encode(&stored.identity_key),
        signed_prekey: encode(&stored.signed_prekey),
        signed_prekey_sig: encode(&stored.signed_prekey_sig),
        signed_prekey_id: stored.signed_prekey_id,
        identity_key_ed: optional(stored.identity_key_ed.as_deref()),
        identity_key_sig: optional(stored.identity_key_sig.as_deref()),
        supports_v2: stored.supports_v2,
        device_x3dh_pub: optional(stored.device_x3dh_pub.as_deref()),
        device_sign_pub: optional(stored.device_sign_pub.as_deref()),
        device_cert_sig: optional(stored.device_cert_sig.as_deref()),
        client_device_id: stored.client_device_id.clone(),
        device_kyber_pub: optional(stored.device_kyber_pub.as_deref()),
        device_kyber_sig: optional(stored.device_kyber_sig.as_deref()),
        device_kyber_id: stored.device_kyber_id,
        one_time_prekey: None,
        one_time_prekey_id: None,
    }
}

pub fn bundle_list(user_id: i64, stored: &[StoredBundle]) -> BundleList {
    BundleList {
        user_id,
        bundles: stored.iter().map(device_bundle).collect(),
    }
}

fn optional(bytes: Option<&[u8]>) -> Option<String> {
    bytes.map(encode)
}

#[cfg(test)]
mod tests {
    use super::{bundle_list, bundle_response, device_bundle};
    use crate::prekey::bundle::stored::StoredBundle;

    fn stored() -> StoredBundle {
        StoredBundle {
            device_id: Some(4),
            identity_key: vec![0xaa; 32],
            signed_prekey: vec![0xbb; 32],
            signed_prekey_sig: vec![0xcc; 64],
            signed_prekey_id: 3,
            identity_key_ed: Some(vec![0xdd; 32]),
            identity_key_sig: None,
            supports_v2: Some(true),
            device_x3dh_pub: None,
            device_sign_pub: None,
            device_cert_sig: None,
            client_device_id: Some("0123456789abcdef0123456789abcdef".to_string()),
            device_kyber_pub: None,
            device_kyber_sig: None,
            device_kyber_id: None,
        }
    }

    #[test]
    fn a_fetch_never_hands_out_a_one_time_key() {
        let response = bundle_response(7, &stored());
        assert_eq!(response.user_id, 7);
        assert!(response.bundle.one_time_prekey.is_none());
        assert!(response.bundle.one_time_prekey_id.is_none());
        assert!(device_bundle(&stored()).one_time_prekey.is_none());
    }

    #[test]
    fn absent_columns_stay_absent_and_present_ones_are_hex() {
        let response = bundle_response(1, &stored());
        assert_eq!(response.bundle.identity_key, "aa".repeat(32));
        assert_eq!(response.bundle.identity_key_ed, Some("dd".repeat(32)));
        assert_eq!(response.bundle.identity_key_sig, None);
        assert_eq!(response.bundle.supports_v2, Some(true));
    }

    #[test]
    fn a_list_keeps_the_order_it_was_given() {
        let mut second = stored();
        second.device_id = Some(9);
        let list = bundle_list(2, &[stored(), second]);
        assert_eq!(list.user_id, 2);
        assert_eq!(list.bundles.len(), 2);
        assert_eq!(list.bundles[0].device_id, Some(4));
        assert_eq!(list.bundles[1].device_id, Some(9));
    }

    #[test]
    fn a_single_bundle_and_its_place_in_a_list_are_the_same_shape() {
        assert_eq!(
            bundle_response(1, &stored()).bundle,
            device_bundle(&stored())
        );
    }

    #[test]
    fn the_user_is_named_once_and_only_at_the_top() {
        let json = serde_json::to_string(&bundle_response(7, &stored())).unwrap();
        assert!(json.starts_with(r#"{"user_id":7,"device_id":4"#));
        assert_eq!(json.matches("user_id").count(), 1);
    }
}
