use std::sync::Arc;

use vortex_auth::account::user_id::UserId;
use vortex_auth::ports::clock::Clock;

use crate::error::Result;
use crate::ports::stage_board::StageBoard;
use crate::stage::record::Stage;
use crate::stage::status::StageStatus;
use crate::time::lifetime;
use vortex_core::room::room_id::RoomId;

pub struct StageService {
    board: Arc<dyn StageBoard>,
    clock: Arc<dyn Clock>,
}

impl StageService {
    pub fn new(board: Arc<dyn StageBoard>, clock: Arc<dyn Clock>) -> Self {
        StageService { board, clock }
    }

    pub fn open(&self, room: RoomId, speaker: UserId) -> Result<Stage> {
        let now = self.clock.unix_seconds();
        let stage = Stage::opened_by(speaker.value(), lifetime::presence().expires_at(now));
        self.board.open(room, &stage, now)?;
        Ok(stage)
    }

    pub fn close(&self, room: RoomId) -> Result<bool> {
        self.board.close(room, self.clock.unix_seconds())
    }

    pub fn status(&self, room: RoomId) -> Result<StageStatus> {
        Ok(StageStatus::of(
            self.board.find(room, self.clock.unix_seconds())?,
        ))
    }

    pub fn add(&self, room: RoomId, speaker: UserId) -> Result<Option<Stage>> {
        let now = self.clock.unix_seconds();
        self.board
            .add(room, speaker, lifetime::presence().expires_at(now), now)
    }

    pub fn remove(&self, room: RoomId, speaker: UserId) -> Result<Option<Stage>> {
        let now = self.clock.unix_seconds();
        self.board
            .remove(room, speaker, lifetime::presence().expires_at(now), now)
    }

    pub fn renew(&self, room: RoomId) -> Result<bool> {
        let now = self.clock.unix_seconds();
        self.board
            .renew(room, lifetime::presence().expires_at(now), now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::StageService;
    use crate::error::StateError;
    use crate::stage::memory::MemoryStageBoard;
    use crate::stage::unavailable::UnavailableStageBoard;
    use vortex_auth::account::user_id::UserId;
    use vortex_auth::time::manual_clock::ManualClock;
    use vortex_core::room::room_id::RoomId;

    fn room() -> RoomId {
        RoomId::of(1).unwrap()
    }

    fn service(clock: Arc<ManualClock>) -> StageService {
        StageService::new(Arc::new(MemoryStageBoard::new()), clock)
    }

    #[test]
    fn a_stage_that_was_never_opened_lets_everyone_speak() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let status = service.status(room()).unwrap();
        assert!(!status.open());
        assert!(status.speaks(7));
    }

    #[test]
    fn the_admin_who_opens_the_stage_is_its_first_speaker() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        service.open(room(), UserId::of(7).unwrap()).unwrap();

        let status = service.status(room()).unwrap();
        assert!(status.open());
        assert_eq!(status.speakers(), vec![7]);
        assert!(!status.speaks(8));
    }

    #[test]
    fn a_listener_promoted_to_speaker_is_seen_by_every_worker() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        service.open(room(), UserId::of(7).unwrap()).unwrap();
        service.add(room(), UserId::of(8).unwrap()).unwrap();

        assert_eq!(service.status(room()).unwrap().speakers(), vec![7, 8]);
    }

    #[test]
    fn demoting_the_last_speaker_leaves_the_stage_open() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        service.open(room(), UserId::of(7).unwrap()).unwrap();
        service.remove(room(), UserId::of(7).unwrap()).unwrap();

        let status = service.status(room()).unwrap();
        assert!(status.open());
        assert!(status.speakers().is_empty());
    }

    #[test]
    fn a_stage_nobody_opened_promotes_nobody() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        assert!(service
            .add(room(), UserId::of(8).unwrap())
            .unwrap()
            .is_none());
        assert!(!service.close(room()).unwrap());
    }

    #[test]
    fn a_stage_nobody_renews_closes_by_itself() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        service.open(room(), UserId::of(7).unwrap()).unwrap();

        clock.advance(120.0);
        assert!(!service.status(room()).unwrap().open());
    }

    #[test]
    fn renewing_keeps_a_quiet_stage_open() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        service.open(room(), UserId::of(7).unwrap()).unwrap();

        clock.advance(90.0);
        assert!(service.renew(room()).unwrap());
        clock.advance(90.0);
        assert!(service.status(room()).unwrap().open());
    }

    #[test]
    fn without_shared_state_the_stage_refuses_instead_of_answering_for_one_worker() {
        let service = StageService::new(
            Arc::new(UnavailableStageBoard::new()),
            Arc::new(ManualClock::at(1_000.0)),
        );
        assert_eq!(
            service.open(room(), UserId::of(7).unwrap()),
            Err(StateError::Unavailable)
        );
    }
}
