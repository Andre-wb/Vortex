use pyo3::prelude::*;

mod messages;
pub use messages::{
    crypt::{decrypt_message, encrypt_message},
    hash::{generate_key, hash_message},
    ChatStats,
};

mod auth;
use auth::{
    passwords::{hash_password, verify_password},
    tokens::{hash_token, verify_token},
};

pub mod auth_state;
pub mod delivery;
pub mod push;
pub mod registry;
pub mod resume;
use delivery::api::{
    delivery_connect_redis, delivery_is_repeat, delivery_is_shared, delivery_mode,
    delivery_notification_collect, delivery_notification_deposit, delivery_notification_tally,
    delivery_room_collect, delivery_room_deposit, delivery_room_sweep, delivery_room_tally,
    delivery_seen_count,
};
use push::api::{
    push_connect_redis, push_is_shared, push_mode, push_register, push_registrations, push_tally,
    push_unregister, push_wake,
};
use registry::api::{
    registry_alive, registry_connect_redis, registry_count, registry_find, registry_forget_dead,
    registry_heard, registry_is_shared, registry_mode, registry_next_virtual_room,
    registry_own_address, registry_reserve_virtual_room, registry_rooms_of_the_living,
    registry_set_own_address, registry_set_rooms, registry_set_timeout,
};
use resume::api::{
    resume_connect_redis, resume_cursor_count, resume_cursor_find, resume_cursor_forget,
    resume_cursor_save, resume_is_shared, resume_mode, resume_upload_close, resume_upload_count,
    resume_upload_find, resume_upload_limits, resume_upload_open, resume_upload_plan,
    resume_upload_receive, resume_upload_sweep,
};

pub mod live;
use auth_state::api::{
    auth_access_revoked, auth_arm_password_marker, auth_burn_password_marker, auth_connect_redis,
    auth_entry_login_allowed, auth_entry_register_allowed, auth_handoff_accept,
    auth_handoff_forget_all, auth_handoff_seen, auth_handoff_token_seconds, auth_login_claim,
    auth_login_issue, auth_login_issue_decoy, auth_passkey_claim_login,
    auth_passkey_claim_registration, auth_passkey_open_login, auth_passkey_open_registration,
    auth_password_marker_armed, auth_qr_answer, auth_qr_confirm, auth_qr_hand_over, auth_qr_open,
    auth_revoke_access, auth_state_is_shared, auth_state_mode, auth_totp_attempt_allowed,
    auth_wallet_burn, auth_wallet_check, auth_wallet_issue,
};
use auth_state::login::{PyLoginChallenge, PyLoginClaim};
use auth_state::passkey::PyPasskeyClaim;
use auth_state::qr::{PyQrAnswer, PyQrHandover, PyQrSession};
use auth_state::wallet::{PyWalletChallenge, PyWalletCheck};
use live::api::{
    live_call_active, live_call_add, live_call_decline, live_call_end, live_call_join,
    live_call_leave, live_call_renew, live_call_ring_out, live_call_start, live_call_status,
    live_connect_redis, live_is_shared, live_mode, live_recording_start, live_recording_status,
    live_recording_stop, live_schedule_claim_due, live_schedule_find, live_schedule_forget,
    live_schedule_plan, live_stage_add, live_stage_close, live_stage_open, live_stage_remove,
    live_stage_status, live_stream_donate, live_stream_grant, live_stream_hands, live_stream_join,
    live_stream_kick, live_stream_leave, live_stream_lower_hand, live_stream_mute,
    live_stream_open, live_stream_raise_hand, live_stream_react, live_stream_renew,
    live_stream_share_screen, live_stream_status, live_stream_stop, live_stream_update,
    live_voice_count, live_voice_find, live_voice_join, live_voice_leave, live_voice_mute,
    live_voice_participants, live_voice_renew,
};

pub mod ratelimit;
use ratelimit::api::{
    ratelimit_assistant_allowed, ratelimit_connect_redis, ratelimit_flood_check,
    ratelimit_flood_forget, ratelimit_gossip_allowed, ratelimit_guest_login_allowed,
    ratelimit_is_shared, ratelimit_link_spam, ratelimit_mode, ratelimit_node_allowed,
    ratelimit_notification_pair_allowed, ratelimit_notification_sender_allowed,
    ratelimit_preview_account_allowed, ratelimit_preview_address_allowed,
    ratelimit_pseudonym_resolve_allowed, ratelimit_push_register_allowed,
    ratelimit_push_wake_allowed, ratelimit_repeat_spam, ratelimit_replication_allowed,
    ratelimit_secrets_account_allowed, ratelimit_secrets_address_allowed,
    ratelimit_shard_store_allowed, ratelimit_signal_allowed, ratelimit_translation_allowed,
    ratelimit_vault_read_allowed,
};

mod udp_broadcast;
use udp_broadcast::api::{
    udp_decode, udp_encode, udp_stealth_open, udp_stealth_port, udp_stealth_seal,
    udp_stealth_seal_random, udp_subnet_broadcast,
};
use udp_broadcast::start_discovery;

mod crypto;
use crypto::handshake::{derive_session_key, generate_keypair};

pub mod bmp;
use bmp::api::*;
use bmp::batch::PyBmpBatch;
use bmp::limits::limits_dict;
use bmp::rejection::PyBmpRejection;

pub mod proto;
use proto::api::{
    prekey_bundle_list, prekey_bundle_response, prekey_claim_response, prekey_client_device_id,
    prekey_limits, prekey_needs_replenishment, prekey_parse_publish, prekey_status_published,
    prekey_status_unpublished,
};
use proto::message::{message_frame_too_large, message_read, PyIncomingMessage, PyMessageRefusal};
use proto::publish::PyPreKeyPublish;
use proto::rejection::PyProtoRejection;

use proto::relay::{
    message_ack, message_ack_duplicate, message_client_stamp, message_deleted, message_edited,
    message_enc_version, message_sent, message_stored, message_thread_sent, message_thread_update,
    message_wire_stamp,
};
use proto::room::{
    room_antispam_config, room_avatar_given, room_description_read, room_name_read,
    room_replication_mode, room_settings_parse, room_theme, room_view, PyRoomSettings,
};
use proto::stored::PyStoredBundle;
use proto::wire_limits::{message_limits_dict, room_limits_dict, wrapped_key_limits_dict};
use proto::wrap::{wrapped_key_parse, wrapped_key_stored, PyWrappedKey};

pub mod storage;
use storage::api::{
    storage_add_one_time_keys, storage_all_bundles, storage_available_one_time_keys,
    storage_bundle_of_device, storage_connect_postgres, storage_device_of, storage_is_connected,
    storage_newest_bundle, storage_save_bundle, storage_take_one_time_key,
};
use storage::directories::{
    storage_bot_scopes, storage_clear_draft, storage_draft_of, storage_forget_stale_drafts,
    storage_forget_webhook, storage_inline_results, storage_keep_newest_inline,
    storage_list_distributed, storage_locate_distributed, storage_record_unified_delivery,
    storage_register_distributed, storage_register_unified_push, storage_remember_inline,
    storage_replace_bot_scopes, storage_save_draft, storage_save_webhook, storage_unified_push_of,
    storage_unregister_unified_push, storage_webhook_of,
};
use storage::record::PyBundleRecord;

pub mod pq;
use pq::pybridge::{
    mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_encapsulate_derand, mlkem768_keygen,
    mlkem768_keygen_derand, pq_hybrid_combine,
};

mod sealed_sender;
use sealed_sender::{compute_sender_pseudo, compute_sender_pseudo_batch, verify_sender_pseudo};
mod canonical_json;
use canonical_json::{canonical_json as canonical_json_fn, sign_canonical};
mod ratchet_kdf;
use ratchet_kdf::{
    ratchet_advance_chain, ratchet_decrypt_step, ratchet_encrypt_step, ratchet_kdf_ck,
    ratchet_kdf_rk, ratchet_message_key, ratchet_root_kdf,
};
mod integrity_walk;
use integrity_walk::{sha256_manifest_walk, verify_manifest};
mod steganography;
use steganography::{steg_embed_bytes, steg_embed_png, steg_extract_png};
mod metadata_padding;
use metadata_padding::{pad_bucket_for, pad_to_bucket, unpad_from_bucket};
mod batch_verify;
use batch_verify::{batch_verify as ed_batch_verify, verify_signature as ed_verify};
mod chunk_hash;
use chunk_hash::{sha256_combine_hex, sha256_concat_hex, sha256_hex, sha256_stream};
pub mod transport;
use transport::browser_bridge::{
    chrome_headers, header_order, PyCookieJar, PyEntropyEnvelope, PyRefererChain,
};
use transport::censorship_bridge::{PyCensorshipDashboard, PyCensorshipRejection};
use transport::latency_bridge::PyLatencyMonitor;
use transport::naive_bridge::PyNaive;
use transport::obfuscation_bridge::{
    PyObfuscation, PyObfuscationFrameStep, PyObfuscationFrames, PyObfuscationSession,
    PyTrafficNormalizer,
};
use transport::pacing_bridge::{PyBurstPlan, PyPacketLoss, PyRotationSchedule};
use transport::probe_bridge::{PyCensorshipProbe, PyProbeTarget};
use transport::probe_detector_bridge::PyProbeDetector;
use transport::reality_bridge::PyRealityAuth;
use transport::shadowsocks_bridge::{PyShadowsocks, PyShadowsocksFrameStep, PyShadowsocksSession};
use transport::shadowtls_bridge::{
    PyShadowTls, PyShadowTlsClientStep, PyShadowTlsConnection, PyShadowTlsDonorStep,
    PyShadowTlsStream,
};
use transport::sw_bridge::PyServiceWorkerProfile;
use transport::timeout_bridge::{handshake_timeout_secs, PyReadDeadline};
use transport::trojan_bridge::{PyTrojan, PyTrojanRequest};
use transport::tunnel_bridge::{dns_addresses, dns_query, PyDohTunnel, PyDomainGenerator};

#[pymodule]
fn vortex_chat(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let _ = pyo3_log::Logger::default()
        .filter(log::LevelFilter::Trace)
        .install();

    m.add_function(wrap_pyfunction!(hash_message, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_message, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_message, m)?)?;
    m.add_function(wrap_pyfunction!(hash_password, m)?)?;
    m.add_function(wrap_pyfunction!(verify_password, m)?)?;
    m.add_function(wrap_pyfunction!(hash_token, m)?)?;
    m.add_function(wrap_pyfunction!(verify_token, m)?)?;
    m.add_function(wrap_pyfunction!(start_discovery, m)?)?;
    m.add_function(wrap_pyfunction!(udp_encode, m)?)?;
    m.add_function(wrap_pyfunction!(udp_decode, m)?)?;
    m.add_function(wrap_pyfunction!(udp_stealth_seal, m)?)?;
    m.add_function(wrap_pyfunction!(udp_stealth_seal_random, m)?)?;
    m.add_function(wrap_pyfunction!(udp_stealth_open, m)?)?;
    m.add_function(wrap_pyfunction!(udp_stealth_port, m)?)?;
    m.add_function(wrap_pyfunction!(udp_subnet_broadcast, m)?)?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(derive_session_key, m)?)?;
    m.add_class::<ChatStats>()?;

    m.add("BMP_LIMITS", limits_dict(m.py())?)?;
    m.add_class::<PyBmpRejection>()?;
    m.add_class::<PyBmpBatch>()?;
    m.add_function(wrap_pyfunction!(bmp_connect_redis, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_is_shared, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_deposit, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_fetch_batch, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_gc, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_stats, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_compute_mailbox_id, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_compute_mailbox_ids, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_pair_jitter, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_set_room_secret, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_get_room_secret, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_remove_room_secret, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_deposit_envelope, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_bucket_timestamp, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_wake_category, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_start_gc, m)?)?;

    m.add_function(wrap_pyfunction!(delivery_connect_redis, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_mode, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_is_shared, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_is_repeat, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_seen_count, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_room_deposit, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_room_collect, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_room_sweep, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_room_tally, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_notification_deposit, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_notification_collect, m)?)?;
    m.add_function(wrap_pyfunction!(delivery_notification_tally, m)?)?;
    m.add_function(wrap_pyfunction!(registry_connect_redis, m)?)?;
    m.add_function(wrap_pyfunction!(registry_mode, m)?)?;
    m.add_function(wrap_pyfunction!(registry_is_shared, m)?)?;
    m.add_function(wrap_pyfunction!(registry_set_timeout, m)?)?;
    m.add_function(wrap_pyfunction!(registry_own_address, m)?)?;
    m.add_function(wrap_pyfunction!(registry_set_own_address, m)?)?;
    m.add_function(wrap_pyfunction!(registry_heard, m)?)?;
    m.add_function(wrap_pyfunction!(registry_find, m)?)?;
    m.add_function(wrap_pyfunction!(registry_alive, m)?)?;
    m.add_function(wrap_pyfunction!(registry_forget_dead, m)?)?;
    m.add_function(wrap_pyfunction!(registry_set_rooms, m)?)?;
    m.add_function(wrap_pyfunction!(registry_rooms_of_the_living, m)?)?;
    m.add_function(wrap_pyfunction!(registry_count, m)?)?;
    m.add_function(wrap_pyfunction!(registry_next_virtual_room, m)?)?;
    m.add_function(wrap_pyfunction!(registry_reserve_virtual_room, m)?)?;
    m.add_function(wrap_pyfunction!(push_connect_redis, m)?)?;
    m.add_function(wrap_pyfunction!(push_mode, m)?)?;
    m.add_function(wrap_pyfunction!(push_is_shared, m)?)?;
    m.add_function(wrap_pyfunction!(push_register, m)?)?;
    m.add_function(wrap_pyfunction!(push_unregister, m)?)?;
    m.add_function(wrap_pyfunction!(push_wake, m)?)?;
    m.add_function(wrap_pyfunction!(push_registrations, m)?)?;
    m.add_function(wrap_pyfunction!(push_tally, m)?)?;
    m.add_function(wrap_pyfunction!(resume_connect_redis, m)?)?;
    m.add_function(wrap_pyfunction!(resume_mode, m)?)?;
    m.add_function(wrap_pyfunction!(resume_is_shared, m)?)?;
    m.add_function(wrap_pyfunction!(resume_upload_limits, m)?)?;
    m.add_function(wrap_pyfunction!(resume_upload_plan, m)?)?;
    m.add_function(wrap_pyfunction!(resume_upload_open, m)?)?;
    m.add_function(wrap_pyfunction!(resume_upload_find, m)?)?;
    m.add_function(wrap_pyfunction!(resume_upload_receive, m)?)?;
    m.add_function(wrap_pyfunction!(resume_upload_close, m)?)?;
    m.add_function(wrap_pyfunction!(resume_upload_sweep, m)?)?;
    m.add_function(wrap_pyfunction!(resume_upload_count, m)?)?;
    m.add_function(wrap_pyfunction!(resume_cursor_save, m)?)?;
    m.add_function(wrap_pyfunction!(resume_cursor_find, m)?)?;
    m.add_function(wrap_pyfunction!(resume_cursor_forget, m)?)?;
    m.add_function(wrap_pyfunction!(resume_cursor_count, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_connect_redis, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_mode, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_is_shared, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_secrets_address_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_secrets_account_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_gossip_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_flood_check, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_flood_forget, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_vault_read_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_notification_sender_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_notification_pair_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_translation_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_preview_account_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_preview_address_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_assistant_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_replication_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_node_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_push_register_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_push_wake_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_pseudonym_resolve_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_guest_login_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_shard_store_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_signal_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_repeat_spam, m)?)?;
    m.add_function(wrap_pyfunction!(ratelimit_link_spam, m)?)?;

    m.add_function(wrap_pyfunction!(live_connect_redis, m)?)?;
    m.add_function(wrap_pyfunction!(live_mode, m)?)?;
    m.add_function(wrap_pyfunction!(live_is_shared, m)?)?;
    m.add_function(wrap_pyfunction!(live_voice_join, m)?)?;
    m.add_function(wrap_pyfunction!(live_voice_leave, m)?)?;
    m.add_function(wrap_pyfunction!(live_voice_participants, m)?)?;
    m.add_function(wrap_pyfunction!(live_voice_count, m)?)?;
    m.add_function(wrap_pyfunction!(live_voice_find, m)?)?;
    m.add_function(wrap_pyfunction!(live_voice_mute, m)?)?;
    m.add_function(wrap_pyfunction!(live_voice_renew, m)?)?;
    m.add_function(wrap_pyfunction!(live_stage_open, m)?)?;
    m.add_function(wrap_pyfunction!(live_stage_close, m)?)?;
    m.add_function(wrap_pyfunction!(live_stage_status, m)?)?;
    m.add_function(wrap_pyfunction!(live_stage_add, m)?)?;
    m.add_function(wrap_pyfunction!(live_stage_remove, m)?)?;
    m.add_function(wrap_pyfunction!(live_recording_start, m)?)?;
    m.add_function(wrap_pyfunction!(live_recording_stop, m)?)?;
    m.add_function(wrap_pyfunction!(live_recording_status, m)?)?;
    m.add_function(wrap_pyfunction!(live_call_start, m)?)?;
    m.add_function(wrap_pyfunction!(live_call_join, m)?)?;
    m.add_function(wrap_pyfunction!(live_call_decline, m)?)?;
    m.add_function(wrap_pyfunction!(live_call_leave, m)?)?;
    m.add_function(wrap_pyfunction!(live_call_add, m)?)?;
    m.add_function(wrap_pyfunction!(live_call_end, m)?)?;
    m.add_function(wrap_pyfunction!(live_call_ring_out, m)?)?;
    m.add_function(wrap_pyfunction!(live_call_status, m)?)?;
    m.add_function(wrap_pyfunction!(live_call_active, m)?)?;
    m.add_function(wrap_pyfunction!(live_call_renew, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_open, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_stop, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_join, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_leave, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_status, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_raise_hand, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_lower_hand, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_hands, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_grant, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_kick, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_react, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_donate, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_update, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_mute, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_share_screen, m)?)?;
    m.add_function(wrap_pyfunction!(live_stream_renew, m)?)?;
    m.add_function(wrap_pyfunction!(live_schedule_plan, m)?)?;
    m.add_function(wrap_pyfunction!(live_schedule_find, m)?)?;
    m.add_function(wrap_pyfunction!(live_schedule_forget, m)?)?;
    m.add_function(wrap_pyfunction!(live_schedule_claim_due, m)?)?;

    m.add_function(wrap_pyfunction!(auth_connect_redis, m)?)?;
    m.add_function(wrap_pyfunction!(auth_state_mode, m)?)?;
    m.add_function(wrap_pyfunction!(auth_state_is_shared, m)?)?;
    m.add_function(wrap_pyfunction!(auth_revoke_access, m)?)?;
    m.add_function(wrap_pyfunction!(auth_access_revoked, m)?)?;
    m.add_function(wrap_pyfunction!(auth_arm_password_marker, m)?)?;
    m.add_function(wrap_pyfunction!(auth_password_marker_armed, m)?)?;
    m.add_function(wrap_pyfunction!(auth_burn_password_marker, m)?)?;
    m.add_function(wrap_pyfunction!(auth_entry_login_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(auth_entry_register_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(auth_totp_attempt_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(auth_handoff_seen, m)?)?;
    m.add_function(wrap_pyfunction!(auth_handoff_accept, m)?)?;
    m.add_function(wrap_pyfunction!(auth_handoff_forget_all, m)?)?;
    m.add_function(wrap_pyfunction!(auth_handoff_token_seconds, m)?)?;
    m.add_function(wrap_pyfunction!(auth_wallet_issue, m)?)?;
    m.add_function(wrap_pyfunction!(auth_wallet_check, m)?)?;
    m.add_function(wrap_pyfunction!(auth_wallet_burn, m)?)?;
    m.add_function(wrap_pyfunction!(auth_passkey_open_registration, m)?)?;
    m.add_function(wrap_pyfunction!(auth_passkey_open_login, m)?)?;
    m.add_function(wrap_pyfunction!(auth_passkey_claim_registration, m)?)?;
    m.add_function(wrap_pyfunction!(auth_passkey_claim_login, m)?)?;
    m.add_function(wrap_pyfunction!(auth_login_issue, m)?)?;
    m.add_function(wrap_pyfunction!(auth_login_issue_decoy, m)?)?;
    m.add_function(wrap_pyfunction!(auth_login_claim, m)?)?;
    m.add_function(wrap_pyfunction!(auth_qr_open, m)?)?;
    m.add_function(wrap_pyfunction!(auth_qr_answer, m)?)?;
    m.add_function(wrap_pyfunction!(auth_qr_confirm, m)?)?;
    m.add_function(wrap_pyfunction!(auth_qr_hand_over, m)?)?;
    m.add_class::<PyPasskeyClaim>()?;
    m.add_class::<PyLoginChallenge>()?;
    m.add_class::<PyLoginClaim>()?;
    m.add_class::<PyQrSession>()?;
    m.add_class::<PyQrAnswer>()?;
    m.add_class::<PyQrHandover>()?;
    m.add_class::<PyWalletChallenge>()?;
    m.add_class::<PyWalletCheck>()?;

    m.add("PREKEY_LIMITS", prekey_limits(m.py())?)?;
    m.add_class::<PyProtoRejection>()?;
    m.add_class::<PyPreKeyPublish>()?;
    m.add_class::<PyStoredBundle>()?;
    m.add_function(wrap_pyfunction!(prekey_parse_publish, m)?)?;
    m.add_function(wrap_pyfunction!(prekey_bundle_response, m)?)?;
    m.add_function(wrap_pyfunction!(prekey_bundle_list, m)?)?;
    m.add_function(wrap_pyfunction!(prekey_claim_response, m)?)?;
    m.add_function(wrap_pyfunction!(prekey_status_unpublished, m)?)?;
    m.add_function(wrap_pyfunction!(prekey_status_published, m)?)?;
    m.add_function(wrap_pyfunction!(prekey_needs_replenishment, m)?)?;
    m.add_function(wrap_pyfunction!(prekey_client_device_id, m)?)?;

    m.add_class::<PyBundleRecord>()?;
    m.add_function(wrap_pyfunction!(storage_connect_postgres, m)?)?;
    m.add_function(wrap_pyfunction!(storage_is_connected, m)?)?;
    m.add_function(wrap_pyfunction!(storage_newest_bundle, m)?)?;
    m.add_function(wrap_pyfunction!(storage_bundle_of_device, m)?)?;
    m.add_function(wrap_pyfunction!(storage_all_bundles, m)?)?;
    m.add_function(wrap_pyfunction!(storage_save_bundle, m)?)?;
    m.add_function(wrap_pyfunction!(storage_add_one_time_keys, m)?)?;
    m.add_function(wrap_pyfunction!(storage_take_one_time_key, m)?)?;
    m.add_function(wrap_pyfunction!(storage_available_one_time_keys, m)?)?;
    m.add_function(wrap_pyfunction!(storage_device_of, m)?)?;
    m.add_function(wrap_pyfunction!(storage_webhook_of, m)?)?;
    m.add_function(wrap_pyfunction!(storage_save_webhook, m)?)?;
    m.add_function(wrap_pyfunction!(storage_forget_webhook, m)?)?;
    m.add_function(wrap_pyfunction!(storage_bot_scopes, m)?)?;
    m.add_function(wrap_pyfunction!(storage_replace_bot_scopes, m)?)?;
    m.add_function(wrap_pyfunction!(storage_inline_results, m)?)?;
    m.add_function(wrap_pyfunction!(storage_remember_inline, m)?)?;
    m.add_function(wrap_pyfunction!(storage_keep_newest_inline, m)?)?;
    m.add_function(wrap_pyfunction!(storage_draft_of, m)?)?;
    m.add_function(wrap_pyfunction!(storage_save_draft, m)?)?;
    m.add_function(wrap_pyfunction!(storage_clear_draft, m)?)?;
    m.add_function(wrap_pyfunction!(storage_forget_stale_drafts, m)?)?;
    m.add_function(wrap_pyfunction!(storage_register_distributed, m)?)?;
    m.add_function(wrap_pyfunction!(storage_locate_distributed, m)?)?;
    m.add_function(wrap_pyfunction!(storage_list_distributed, m)?)?;
    m.add_function(wrap_pyfunction!(storage_unified_push_of, m)?)?;
    m.add_function(wrap_pyfunction!(storage_register_unified_push, m)?)?;
    m.add_function(wrap_pyfunction!(storage_unregister_unified_push, m)?)?;
    m.add_function(wrap_pyfunction!(storage_record_unified_delivery, m)?)?;

    m.add("MESSAGE_LIMITS", message_limits_dict(m.py())?)?;
    m.add("ROOM_LIMITS", room_limits_dict(m.py())?)?;
    m.add("WRAPPED_KEY_LIMITS", wrapped_key_limits_dict(m.py())?)?;
    m.add_class::<PyMessageRefusal>()?;
    m.add_class::<PyIncomingMessage>()?;
    m.add_class::<PyWrappedKey>()?;
    m.add_class::<PyRoomSettings>()?;
    m.add_function(wrap_pyfunction!(message_read, m)?)?;
    m.add_function(wrap_pyfunction!(message_frame_too_large, m)?)?;
    m.add_function(wrap_pyfunction!(message_ack, m)?)?;
    m.add_function(wrap_pyfunction!(message_ack_duplicate, m)?)?;
    m.add_function(wrap_pyfunction!(message_sent, m)?)?;
    m.add_function(wrap_pyfunction!(message_thread_sent, m)?)?;
    m.add_function(wrap_pyfunction!(message_edited, m)?)?;
    m.add_function(wrap_pyfunction!(message_deleted, m)?)?;
    m.add_function(wrap_pyfunction!(message_thread_update, m)?)?;
    m.add_function(wrap_pyfunction!(message_stored, m)?)?;
    m.add_function(wrap_pyfunction!(message_wire_stamp, m)?)?;
    m.add_function(wrap_pyfunction!(message_client_stamp, m)?)?;
    m.add_function(wrap_pyfunction!(message_enc_version, m)?)?;
    m.add_function(wrap_pyfunction!(wrapped_key_parse, m)?)?;
    m.add_function(wrap_pyfunction!(wrapped_key_stored, m)?)?;
    m.add_function(wrap_pyfunction!(room_settings_parse, m)?)?;
    m.add_function(wrap_pyfunction!(room_name_read, m)?)?;
    m.add_function(wrap_pyfunction!(room_description_read, m)?)?;
    m.add_function(wrap_pyfunction!(room_avatar_given, m)?)?;
    m.add_function(wrap_pyfunction!(room_replication_mode, m)?)?;
    m.add_function(wrap_pyfunction!(room_antispam_config, m)?)?;
    m.add_function(wrap_pyfunction!(room_theme, m)?)?;
    m.add_function(wrap_pyfunction!(room_view, m)?)?;

    m.add_function(wrap_pyfunction!(compute_sender_pseudo, m)?)?;
    m.add_function(wrap_pyfunction!(verify_sender_pseudo, m)?)?;
    m.add_function(wrap_pyfunction!(compute_sender_pseudo_batch, m)?)?;

    m.add_function(wrap_pyfunction!(canonical_json_fn, m)?)?;
    m.add_function(wrap_pyfunction!(sign_canonical, m)?)?;

    m.add_function(wrap_pyfunction!(ratchet_advance_chain, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_message_key, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_encrypt_step, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_decrypt_step, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_root_kdf, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_kdf_rk, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_kdf_ck, m)?)?;

    m.add_function(wrap_pyfunction!(sha256_manifest_walk, m)?)?;
    m.add_function(wrap_pyfunction!(verify_manifest, m)?)?;

    m.add_function(wrap_pyfunction!(steg_embed_png, m)?)?;
    m.add_function(wrap_pyfunction!(steg_extract_png, m)?)?;
    m.add_function(wrap_pyfunction!(steg_embed_bytes, m)?)?;

    m.add_function(wrap_pyfunction!(pad_to_bucket, m)?)?;
    m.add_function(wrap_pyfunction!(unpad_from_bucket, m)?)?;
    m.add_function(wrap_pyfunction!(pad_bucket_for, m)?)?;

    m.add_function(wrap_pyfunction!(ed_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ed_batch_verify, m)?)?;

    m.add_function(wrap_pyfunction!(sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_concat_hex, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_combine_hex, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_stream, m)?)?;

    m.add_function(wrap_pyfunction!(mlkem768_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem768_encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem768_decapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem768_keygen_derand, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem768_encapsulate_derand, m)?)?;
    m.add_function(wrap_pyfunction!(pq_hybrid_combine, m)?)?;
    m.add_function(wrap_pyfunction!(header_order, m)?)?;
    m.add_function(wrap_pyfunction!(chrome_headers, m)?)?;
    m.add_function(wrap_pyfunction!(dns_query, m)?)?;
    m.add_function(wrap_pyfunction!(dns_addresses, m)?)?;

    m.add_class::<PyRealityAuth>()?;
    m.add_class::<PyShadowsocks>()?;
    m.add_class::<PyShadowsocksSession>()?;
    m.add_class::<PyShadowsocksFrameStep>()?;
    m.add_class::<PyShadowTls>()?;
    m.add_class::<PyShadowTlsConnection>()?;
    m.add_class::<PyShadowTlsClientStep>()?;
    m.add_class::<PyShadowTlsDonorStep>()?;
    m.add_class::<PyShadowTlsStream>()?;
    m.add_class::<PyTrojan>()?;
    m.add_class::<PyTrojanRequest>()?;
    m.add_class::<PyNaive>()?;
    m.add_class::<PyReadDeadline>()?;
    m.add_class::<PyObfuscation>()?;
    m.add_class::<PyTrafficNormalizer>()?;
    m.add_class::<PyObfuscationFrames>()?;
    m.add_class::<PyObfuscationSession>()?;
    m.add_class::<PyObfuscationFrameStep>()?;
    m.add_class::<PyCensorshipProbe>()?;
    m.add_class::<PyProbeTarget>()?;
    m.add_class::<PyLatencyMonitor>()?;
    m.add_class::<PyCensorshipDashboard>()?;
    m.add_class::<PyCensorshipRejection>()?;
    m.add_class::<PyServiceWorkerProfile>()?;
    m.add_class::<PyProbeDetector>()?;
    m.add_class::<PyCookieJar>()?;
    m.add_class::<PyRefererChain>()?;
    m.add_class::<PyEntropyEnvelope>()?;
    m.add_class::<PyDomainGenerator>()?;
    m.add_class::<PyDohTunnel>()?;
    m.add_class::<PyBurstPlan>()?;
    m.add_class::<PyPacketLoss>()?;
    m.add_class::<PyRotationSchedule>()?;

    m.add("HANDSHAKE_TIMEOUT_SECS", handshake_timeout_secs())?;
    m.add("VERSION", env!("CARGO_PKG_VERSION"))?;
    m.add("KEY_SIZE", 32usize)?;
    m.add("NONCE_SIZE", 12usize)?;
    Ok(())
}
