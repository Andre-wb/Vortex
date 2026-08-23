mod support;

use std::sync::Arc;

use vortex_redis::resume::session_cursors::RedisSessionCursors;
use vortex_redis::resume::upload_sessions::RedisUploadSessions;
use vortex_resume::testing::{
    session_cursors_conformance as cursors, upload_sessions_conformance as uploads,
};

use support::{backbone, unique_prefix};

#[test]
fn redis_keeps_upload_sessions_the_agreed_way() {
    let Some(shared) = backbone(&unique_prefix("resume-uploads")) else {
        return;
    };
    uploads::an_opened_session_is_found_again(Arc::new(RedisUploadSessions::new(shared.clone())));
    uploads::an_unknown_token_names_no_session(Arc::new(RedisUploadSessions::new(shared.clone())));
    uploads::a_session_past_its_lifetime_is_gone(Arc::new(RedisUploadSessions::new(
        shared.clone(),
    )));
    uploads::a_received_chunk_moves_the_progress(Arc::new(RedisUploadSessions::new(
        shared.clone(),
    )));
    uploads::the_same_chunk_twice_is_taken_once(Arc::new(RedisUploadSessions::new(shared.clone())));
    uploads::a_chunk_outside_the_plan_is_refused(Arc::new(RedisUploadSessions::new(
        shared.clone(),
    )));
    uploads::every_chunk_completes_the_session(Arc::new(RedisUploadSessions::new(shared.clone())));
    uploads::a_chunk_for_an_unknown_session_is_refused(Arc::new(RedisUploadSessions::new(
        shared.clone(),
    )));
    uploads::a_closed_session_is_gone(Arc::new(RedisUploadSessions::new(shared.clone())));
    uploads::sweeping_names_only_the_sessions_it_removed(Arc::new(RedisUploadSessions::new(
        shared.clone(),
    )));
    uploads::sessions_do_not_shadow_each_other(Arc::new(RedisUploadSessions::new(shared)));
}

#[test]
fn redis_keeps_session_cursors_the_agreed_way() {
    let Some(shared) = backbone(&unique_prefix("resume-cursors")) else {
        return;
    };
    cursors::a_saved_cursor_is_read_back(Arc::new(RedisSessionCursors::new(shared.clone())));
    cursors::an_unknown_client_names_no_cursor(Arc::new(RedisSessionCursors::new(shared.clone())));
    cursors::a_later_save_replaces_the_earlier_one(Arc::new(RedisSessionCursors::new(
        shared.clone(),
    )));
    cursors::clients_do_not_shadow_each_other(Arc::new(RedisSessionCursors::new(shared.clone())));
    cursors::a_cursor_past_its_lifetime_is_gone(Arc::new(RedisSessionCursors::new(shared.clone())));
    cursors::a_forgotten_cursor_is_gone(Arc::new(RedisSessionCursors::new(shared.clone())));
    cursors::rooms_are_stored_sorted_and_without_repeats(Arc::new(RedisSessionCursors::new(
        shared.clone(),
    )));
    cursors::a_stamp_before_the_epoch_settles_at_zero(Arc::new(RedisSessionCursors::new(shared)));
}
