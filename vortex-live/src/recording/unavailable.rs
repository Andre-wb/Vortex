use crate::error::{Result, StateError};
use crate::ports::recording_marks::RecordingMarks;
use crate::recording::mark::Mark;
use crate::recording::started::Started;
use vortex_core::room::room_id::RoomId;

pub struct UnavailableRecordingMarks;

impl Default for UnavailableRecordingMarks {
    fn default() -> Self {
        UnavailableRecordingMarks::new()
    }
}

impl UnavailableRecordingMarks {
    pub fn new() -> Self {
        UnavailableRecordingMarks
    }
}

impl RecordingMarks for UnavailableRecordingMarks {
    fn start(&self, _room: RoomId, _mark: &Mark, _now: f64) -> Result<Started> {
        Err(StateError::Unavailable)
    }

    fn stop(&self, _room: RoomId, _now: f64) -> Result<Option<Mark>> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _room: RoomId, _now: f64) -> Result<Option<Mark>> {
        Err(StateError::Unavailable)
    }

    fn renew(&self, _room: RoomId, _until: f64, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableRecordingMarks;
    use crate::error::StateError;
    use crate::ports::recording_marks::RecordingMarks;
    use vortex_core::room::room_id::RoomId;

    #[test]
    fn a_recording_that_cannot_be_shared_is_refused_rather_than_kept_for_one_worker() {
        let marks = UnavailableRecordingMarks::new();
        let room = RoomId::of(1).unwrap();
        assert_eq!(marks.find(room, 1_000.0), Err(StateError::Unavailable));
        assert_eq!(marks.stop(room, 1_000.0), Err(StateError::Unavailable));
    }
}
