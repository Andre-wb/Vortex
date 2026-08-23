use std::sync::Arc;

use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;

use crate::ports::upload_sessions::UploadSessions;
use crate::upload::chunk::ChunkIndex;
use crate::upload::file_name::FileName;
use crate::upload::identifier::UploadId;
use crate::upload::limits;
use crate::upload::lookup::{Found, Reception};
use crate::upload::service::UploadSessionService;
use crate::upload::session::Session;

fn session(token: &str, total: u32, opened_at: f64) -> Session {
    Session::opened(
        UploadId::parse(token).unwrap(),
        RoomId::of(3).unwrap(),
        UserId::of(7).unwrap(),
        FileName::parse("payload.bin").unwrap(),
        4096,
        total,
        "ab".repeat(32),
        opened_at,
    )
}

fn id(token: &str) -> UploadId {
    UploadId::parse(token).unwrap()
}

pub fn an_opened_session_is_found_again(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    service.open(&session("one", 4, 1000.0)).unwrap();
    match service.find(&id("one"), 1000.0).unwrap() {
        Found::Live(found) => {
            assert_eq!(found.total_chunks(), 4);
            assert_eq!(found.file_name().written(), "payload.bin");
            assert_eq!(found.room(), RoomId::of(3).unwrap());
            assert_eq!(found.owner(), UserId::of(7).unwrap());
            assert_eq!(found.file_bytes(), 4096);
            assert_eq!(found.file_digest(), "ab".repeat(32));
        }
        other => panic!("ожидалась живая сессия, получено {other:?}"),
    }
}

pub fn an_unknown_token_names_no_session(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    assert_eq!(service.find(&id("absent"), 1000.0).unwrap(), Found::Missing);
}

pub fn a_session_past_its_lifetime_is_gone(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    service.open(&session("two", 4, 1000.0)).unwrap();
    let past = 1000.0 + limits::SESSION_LIFETIME_SECONDS;
    assert_eq!(service.find(&id("two"), past).unwrap(), Found::Expired);
    assert_eq!(service.find(&id("two"), past).unwrap(), Found::Missing);
}

pub fn a_received_chunk_moves_the_progress(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    service.open(&session("three", 4, 1000.0)).unwrap();
    match service
        .receive(&id("three"), ChunkIndex::of(1), 1000.0)
        .unwrap()
    {
        Reception::Accepted(progress) => {
            assert_eq!(progress.received(), 1);
            assert_eq!(progress.missing(), &[0, 2, 3]);
            assert_eq!(progress.percent(), 25.0);
            assert!(!progress.complete());
        }
        other => panic!("ожидался приём куска, получено {other:?}"),
    }
}

pub fn the_same_chunk_twice_is_taken_once(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    service.open(&session("four", 4, 1000.0)).unwrap();
    service
        .receive(&id("four"), ChunkIndex::of(0), 1000.0)
        .unwrap();
    match service
        .receive(&id("four"), ChunkIndex::of(0), 1000.0)
        .unwrap()
    {
        Reception::AlreadyHeld(progress) => assert_eq!(progress.received(), 1),
        other => panic!("ожидался повтор куска, получено {other:?}"),
    }
}

pub fn a_chunk_outside_the_plan_is_refused(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    service.open(&session("five", 4, 1000.0)).unwrap();
    assert_eq!(
        service
            .receive(&id("five"), ChunkIndex::of(4), 1000.0)
            .unwrap(),
        Reception::OutsidePlan { total: 4 }
    );
}

pub fn every_chunk_completes_the_session(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    service.open(&session("six", 3, 1000.0)).unwrap();
    for index in 0..3 {
        service
            .receive(&id("six"), ChunkIndex::of(index), 1000.0)
            .unwrap();
    }
    match service.find(&id("six"), 1000.0).unwrap() {
        Found::Live(found) => {
            assert!(found.progress().complete());
            assert!(found.progress().missing().is_empty());
            assert_eq!(found.progress().percent(), 100.0);
        }
        other => panic!("ожидалась живая сессия, получено {other:?}"),
    }
}

pub fn a_chunk_for_an_unknown_session_is_refused(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    assert_eq!(
        service
            .receive(&id("absent"), ChunkIndex::of(0), 1000.0)
            .unwrap(),
        Reception::Missing
    );
}

pub fn a_closed_session_is_gone(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    service.open(&session("seven", 4, 1000.0)).unwrap();
    assert!(service.close(&id("seven")).unwrap());
    assert!(!service.close(&id("seven")).unwrap());
    assert_eq!(service.find(&id("seven"), 1000.0).unwrap(), Found::Missing);
}

pub fn sweeping_names_only_the_sessions_it_removed(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    let moment = 1000.0 + limits::SESSION_LIFETIME_SECONDS;
    service.open(&session("stale", 4, 1000.0)).unwrap();
    service.open(&session("fresh", 4, moment)).unwrap();
    let swept = service.sweep(moment).unwrap();
    assert!(swept.contains(&id("stale")));
    assert!(!swept.contains(&id("fresh")));
    assert_eq!(service.find(&id("stale"), moment).unwrap(), Found::Missing);
    assert!(matches!(
        service.find(&id("fresh"), moment).unwrap(),
        Found::Live(_)
    ));
}

pub fn sessions_do_not_shadow_each_other(store: Arc<dyn UploadSessions>) {
    let service = UploadSessionService::new(store);
    let before = service.count().unwrap();
    service.open(&session("left", 4, 1000.0)).unwrap();
    service.open(&session("right", 2, 1000.0)).unwrap();
    assert_eq!(service.count().unwrap(), before + 2);
    service
        .receive(&id("left"), ChunkIndex::of(0), 1000.0)
        .unwrap();
    match service.find(&id("right"), 1000.0).unwrap() {
        Found::Live(found) => assert_eq!(found.progress().received(), 0),
        other => panic!("ожидалась живая сессия, получено {other:?}"),
    }
}
