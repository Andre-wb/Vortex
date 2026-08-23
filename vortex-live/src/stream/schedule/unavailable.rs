use crate::error::{Result, StateError};
use crate::ports::stream_schedule::StreamSchedule;
use crate::stream::schedule::entry::ScheduleEntry;
use vortex_core::room::room_id::RoomId;

pub struct UnavailableStreamSchedule;

impl Default for UnavailableStreamSchedule {
    fn default() -> Self {
        UnavailableStreamSchedule::new()
    }
}

impl UnavailableStreamSchedule {
    pub fn new() -> Self {
        UnavailableStreamSchedule
    }
}

impl StreamSchedule for UnavailableStreamSchedule {
    fn put(&self, _room: RoomId, _entry: &ScheduleEntry, _until: f64, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _room: RoomId, _now: f64) -> Result<Option<ScheduleEntry>> {
        Err(StateError::Unavailable)
    }

    fn forget(&self, _room: RoomId, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }

    fn claim_due(&self, _now: f64) -> Result<Option<ScheduleEntry>> {
        Err(StateError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableStreamSchedule;
    use crate::error::StateError;
    use crate::ports::stream_schedule::StreamSchedule;
    use vortex_core::room::room_id::RoomId;

    #[test]
    fn a_schedule_that_cannot_be_shared_is_refused_rather_than_kept_for_one_worker() {
        let schedule = UnavailableStreamSchedule::new();
        assert_eq!(
            schedule.find(RoomId::of(1).unwrap(), 1_000.0),
            Err(StateError::Unavailable)
        );
        assert_eq!(schedule.claim_due(1_000.0), Err(StateError::Unavailable));
    }
}
