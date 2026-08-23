use std::sync::Arc;

use vortex_resume::cursor::memory::MemorySessionCursors;
use vortex_resume::testing::{
    session_cursors_conformance as cursors, upload_sessions_conformance as uploads,
};
use vortex_resume::upload::memory::MemoryUploadSessions;

#[test]
fn memory_keeps_upload_sessions_the_agreed_way() {
    uploads::an_opened_session_is_found_again(Arc::new(MemoryUploadSessions::new()));
    uploads::an_unknown_token_names_no_session(Arc::new(MemoryUploadSessions::new()));
    uploads::a_session_past_its_lifetime_is_gone(Arc::new(MemoryUploadSessions::new()));
    uploads::a_received_chunk_moves_the_progress(Arc::new(MemoryUploadSessions::new()));
    uploads::the_same_chunk_twice_is_taken_once(Arc::new(MemoryUploadSessions::new()));
    uploads::a_chunk_outside_the_plan_is_refused(Arc::new(MemoryUploadSessions::new()));
    uploads::every_chunk_completes_the_session(Arc::new(MemoryUploadSessions::new()));
    uploads::a_chunk_for_an_unknown_session_is_refused(Arc::new(MemoryUploadSessions::new()));
    uploads::a_closed_session_is_gone(Arc::new(MemoryUploadSessions::new()));
    uploads::sweeping_names_only_the_sessions_it_removed(Arc::new(MemoryUploadSessions::new()));
    uploads::sessions_do_not_shadow_each_other(Arc::new(MemoryUploadSessions::new()));
}

#[test]
fn memory_keeps_session_cursors_the_agreed_way() {
    cursors::a_saved_cursor_is_read_back(Arc::new(MemorySessionCursors::new()));
    cursors::an_unknown_client_names_no_cursor(Arc::new(MemorySessionCursors::new()));
    cursors::a_later_save_replaces_the_earlier_one(Arc::new(MemorySessionCursors::new()));
    cursors::clients_do_not_shadow_each_other(Arc::new(MemorySessionCursors::new()));
    cursors::a_cursor_past_its_lifetime_is_gone(Arc::new(MemorySessionCursors::new()));
    cursors::a_forgotten_cursor_is_gone(Arc::new(MemorySessionCursors::new()));
    cursors::rooms_are_stored_sorted_and_without_repeats(Arc::new(MemorySessionCursors::new()));
    cursors::a_stamp_before_the_epoch_settles_at_zero(Arc::new(MemorySessionCursors::new()));
}
