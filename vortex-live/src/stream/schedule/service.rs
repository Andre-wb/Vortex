use std::sync::Arc;

use vortex_auth::ports::clock::Clock;

use crate::error::Result;
use crate::ports::stream_schedule::StreamSchedule;
use crate::stream::schedule::entry::ScheduleEntry;
use crate::time::lifetime;
use vortex_core::room::room_id::RoomId;

pub struct StreamScheduleService {
    schedule: Arc<dyn StreamSchedule>,
    clock: Arc<dyn Clock>,
}

impl StreamScheduleService {
    pub fn new(schedule: Arc<dyn StreamSchedule>, clock: Arc<dyn Clock>) -> Self {
        StreamScheduleService { schedule, clock }
    }

    pub fn plan(
        &self,
        room: RoomId,
        title: &str,
        scheduled_at: &str,
        host_id: i64,
        host_name: &str,
    ) -> Result<Option<ScheduleEntry>> {
        let Some(entry) = ScheduleEntry::of(room.value(), title, scheduled_at, host_id, host_name)
        else {
            return Ok(None);
        };
        let now = self.clock.unix_seconds();
        self.schedule
            .put(room, &entry, lifetime::schedule().expires_at(now), now)?;
        Ok(Some(entry))
    }

    pub fn find(&self, room: RoomId) -> Result<Option<ScheduleEntry>> {
        self.schedule.find(room, self.clock.unix_seconds())
    }

    pub fn forget(&self, room: RoomId) -> Result<bool> {
        self.schedule.forget(room, self.clock.unix_seconds())
    }

    pub fn claim_due(&self) -> Result<Option<ScheduleEntry>> {
        self.schedule.claim_due(self.clock.unix_seconds())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::StreamScheduleService;
    use crate::error::StateError;
    use crate::stream::schedule::memory::MemoryStreamSchedule;
    use crate::stream::schedule::unavailable::UnavailableStreamSchedule;
    use vortex_auth::time::manual_clock::ManualClock;
    use vortex_core::room::room_id::RoomId;

    const NOON: f64 = 1_785_834_930.0;

    fn room() -> RoomId {
        RoomId::of(1).unwrap()
    }

    fn service(clock: Arc<ManualClock>) -> StreamScheduleService {
        StreamScheduleService::new(Arc::new(MemoryStreamSchedule::new()), clock)
    }

    #[test]
    fn a_planned_stream_is_seen_by_every_worker() {
        let service = service(Arc::new(ManualClock::at(NOON - 3_600.0)));
        let planned = service
            .plan(room(), "Показ", "2026-08-04T09:15:30Z", 7, "Ann")
            .unwrap()
            .unwrap();

        assert_eq!(planned.at, NOON as i64);
        assert_eq!(service.find(room()).unwrap().unwrap(), planned);
    }

    #[test]
    fn a_moment_nobody_can_read_is_not_planned_at_all() {
        let service = service(Arc::new(ManualClock::at(NOON)));
        assert!(service
            .plan(room(), "Показ", "завтра", 7, "Ann")
            .unwrap()
            .is_none());
        assert!(service.find(room()).unwrap().is_none());
    }

    #[test]
    fn a_schedule_whose_moment_has_not_come_is_claimed_by_nobody() {
        let service = service(Arc::new(ManualClock::at(NOON - 1.0)));
        service
            .plan(room(), "Показ", "2026-08-04T09:15:30Z", 7, "Ann")
            .unwrap();
        assert!(service.claim_due().unwrap().is_none());
    }

    #[test]
    fn a_due_schedule_is_claimed_by_exactly_one_worker() {
        let service = service(Arc::new(ManualClock::at(NOON)));
        service
            .plan(room(), "Показ", "2026-08-04T09:15:30Z", 7, "Ann")
            .unwrap();

        assert_eq!(service.claim_due().unwrap().unwrap().room_id, 1);
        assert!(service.claim_due().unwrap().is_none());
        assert!(service.find(room()).unwrap().is_none());
    }

    #[test]
    fn the_earliest_due_schedule_is_claimed_first() {
        let service = service(Arc::new(ManualClock::at(NOON)));
        service
            .plan(room(), "Позже", "2026-08-04T09:15:30Z", 7, "Ann")
            .unwrap();
        service
            .plan(
                RoomId::of(2).unwrap(),
                "Раньше",
                "2026-08-04T08:00:00Z",
                7,
                "Ann",
            )
            .unwrap();

        assert_eq!(service.claim_due().unwrap().unwrap().title, "Раньше");
        assert_eq!(service.claim_due().unwrap().unwrap().title, "Позже");
    }

    #[test]
    fn starting_the_stream_forgets_what_was_planned() {
        let service = service(Arc::new(ManualClock::at(NOON - 3_600.0)));
        service
            .plan(room(), "Показ", "2026-08-04T09:15:30Z", 7, "Ann")
            .unwrap();

        assert!(service.forget(room()).unwrap());
        assert!(!service.forget(room()).unwrap());
    }

    #[test]
    fn without_shared_state_the_schedule_refuses_instead_of_answering_for_one_worker() {
        let service = StreamScheduleService::new(
            Arc::new(UnavailableStreamSchedule::new()),
            Arc::new(ManualClock::at(NOON)),
        );
        assert_eq!(service.claim_due(), Err(StateError::Unavailable));
    }
}
