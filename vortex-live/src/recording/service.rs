use std::sync::Arc;

use vortex_auth::account::user_id::UserId;
use vortex_auth::ports::clock::Clock;

use crate::error::Result;
use crate::ports::recording_marks::RecordingMarks;
use crate::recording::mark::Mark;
use crate::recording::started::Started;
use crate::time::{lifetime, stamp};
use vortex_core::room::room_id::RoomId;

pub struct RecordingService {
    marks: Arc<dyn RecordingMarks>,
    clock: Arc<dyn Clock>,
}

impl RecordingService {
    pub fn new(marks: Arc<dyn RecordingMarks>, clock: Arc<dyn Clock>) -> Self {
        RecordingService { marks, clock }
    }

    pub fn start(&self, room: RoomId, by: UserId, participants: Vec<i64>) -> Result<Started> {
        let now = self.clock.unix_seconds();
        let mark = Mark::new(
            by.value(),
            stamp::written(now),
            participants,
            lifetime::presence().expires_at(now),
        );
        self.marks.start(room, &mark, now)
    }

    pub fn stop(&self, room: RoomId) -> Result<Option<Mark>> {
        self.marks.stop(room, self.clock.unix_seconds())
    }

    pub fn status(&self, room: RoomId) -> Result<Option<Mark>> {
        self.marks.find(room, self.clock.unix_seconds())
    }

    pub fn renew(&self, room: RoomId) -> Result<bool> {
        let now = self.clock.unix_seconds();
        self.marks
            .renew(room, lifetime::presence().expires_at(now), now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::RecordingService;
    use crate::error::StateError;
    use crate::recording::memory::MemoryRecordingMarks;
    use crate::recording::unavailable::UnavailableRecordingMarks;
    use vortex_auth::account::user_id::UserId;
    use vortex_auth::time::manual_clock::ManualClock;
    use vortex_core::room::room_id::RoomId;

    fn room() -> RoomId {
        RoomId::of(1).unwrap()
    }

    fn admin() -> UserId {
        UserId::of(7).unwrap()
    }

    fn service(clock: Arc<ManualClock>) -> RecordingService {
        RecordingService::new(Arc::new(MemoryRecordingMarks::new()), clock)
    }

    #[test]
    fn a_recording_is_started_once_and_seen_by_every_worker() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let started = service.start(room(), admin(), vec![7, 8]).unwrap();

        assert!(!started.already_started());
        assert_eq!(started.mark().started_at, "1970-01-01T00:16:40+00:00");
        assert_eq!(started.mark().participants, vec![7, 8]);
        assert!(service
            .start(room(), admin(), vec![])
            .unwrap()
            .already_started());
    }

    #[test]
    fn a_recording_is_stopped_once() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        service.start(room(), admin(), vec![]).unwrap();

        assert_eq!(service.stop(room()).unwrap().unwrap().started_by, 7);
        assert!(service.stop(room()).unwrap().is_none());
        assert!(service.status(room()).unwrap().is_none());
    }

    #[test]
    fn a_recording_nobody_renews_stops_by_itself() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        service.start(room(), admin(), vec![]).unwrap();

        clock.advance(120.0);
        assert!(service.status(room()).unwrap().is_none());
    }

    #[test]
    fn renewing_keeps_a_long_recording_running() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        service.start(room(), admin(), vec![]).unwrap();

        clock.advance(90.0);
        assert!(service.renew(room()).unwrap());
        clock.advance(90.0);
        assert!(service.status(room()).unwrap().is_some());
    }

    #[test]
    fn without_shared_state_the_recording_refuses_instead_of_answering_for_one_worker() {
        let service = RecordingService::new(
            Arc::new(UnavailableRecordingMarks::new()),
            Arc::new(ManualClock::at(1_000.0)),
        );
        assert_eq!(
            service.start(room(), admin(), vec![]),
            Err(StateError::Unavailable)
        );
    }
}
