use vortex_auth::account::user_id::UserId;

use crate::error::{Result, StateError};
use crate::ports::stage_board::StageBoard;
use crate::stage::record::Stage;
use vortex_core::room::room_id::RoomId;

pub struct UnavailableStageBoard;

impl Default for UnavailableStageBoard {
    fn default() -> Self {
        UnavailableStageBoard::new()
    }
}

impl UnavailableStageBoard {
    pub fn new() -> Self {
        UnavailableStageBoard
    }
}

impl StageBoard for UnavailableStageBoard {
    fn open(&self, _room: RoomId, _stage: &Stage, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn close(&self, _room: RoomId, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _room: RoomId, _now: f64) -> Result<Option<Stage>> {
        Err(StateError::Unavailable)
    }

    fn add(
        &self,
        _room: RoomId,
        _speaker: UserId,
        _until: f64,
        _now: f64,
    ) -> Result<Option<Stage>> {
        Err(StateError::Unavailable)
    }

    fn remove(
        &self,
        _room: RoomId,
        _speaker: UserId,
        _until: f64,
        _now: f64,
    ) -> Result<Option<Stage>> {
        Err(StateError::Unavailable)
    }

    fn renew(&self, _room: RoomId, _until: f64, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableStageBoard;
    use crate::error::StateError;
    use crate::ports::stage_board::StageBoard;
    use vortex_core::room::room_id::RoomId;

    #[test]
    fn a_stage_that_cannot_be_shared_is_refused_rather_than_kept_for_one_worker() {
        let board = UnavailableStageBoard::new();
        let room = RoomId::of(1).unwrap();
        assert_eq!(board.find(room, 1_000.0), Err(StateError::Unavailable));
        assert_eq!(board.close(room, 1_000.0), Err(StateError::Unavailable));
    }
}
