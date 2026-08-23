use std::collections::BTreeMap;

use vortex_auth::account::user_id::UserId;

use crate::error::{Result, StateError};
use crate::ports::stream_donations::StreamDonations;
use crate::ports::stream_hands::StreamHands;
use crate::ports::stream_records::StreamRecords;
use crate::ports::stream_roster::StreamRoster;
use crate::ports::stream_tally::StreamTally;
use crate::store::swapped::Swapped;
use crate::stream::donation::Donation;
use crate::stream::participant::StreamParticipant;
use crate::stream::record::Stream;
use vortex_core::room::room_id::RoomId;

pub struct UnavailableStreamRecords;

impl Default for UnavailableStreamRecords {
    fn default() -> Self {
        UnavailableStreamRecords::new()
    }
}

impl UnavailableStreamRecords {
    pub fn new() -> Self {
        UnavailableStreamRecords
    }
}

impl StreamRecords for UnavailableStreamRecords {
    fn open(&self, _room: RoomId, _stream: &Stream, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _room: RoomId, _now: f64) -> Result<Option<Stream>> {
        Err(StateError::Unavailable)
    }

    fn swap(
        &self,
        _room: RoomId,
        _expected: &Stream,
        _replacement: &Stream,
        _now: f64,
    ) -> Result<Swapped> {
        Err(StateError::Unavailable)
    }

    fn forget(&self, _room: RoomId, _now: f64) -> Result<Option<Stream>> {
        Err(StateError::Unavailable)
    }
}

pub struct UnavailableStreamRoster;

impl Default for UnavailableStreamRoster {
    fn default() -> Self {
        UnavailableStreamRoster::new()
    }
}

impl UnavailableStreamRoster {
    pub fn new() -> Self {
        UnavailableStreamRoster
    }
}

impl StreamRoster for UnavailableStreamRoster {
    fn seat(
        &self,
        _room: RoomId,
        _participant: &StreamParticipant,
        _until: f64,
        _now: f64,
    ) -> Result<Option<StreamParticipant>> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _room: RoomId, _user: UserId, _now: f64) -> Result<Option<StreamParticipant>> {
        Err(StateError::Unavailable)
    }

    fn list(&self, _room: RoomId, _now: f64) -> Result<Vec<StreamParticipant>> {
        Err(StateError::Unavailable)
    }

    fn swap_member(
        &self,
        _room: RoomId,
        _user: UserId,
        _expected: &StreamParticipant,
        _replacement: &StreamParticipant,
        _until: f64,
        _now: f64,
    ) -> Result<Swapped> {
        Err(StateError::Unavailable)
    }

    fn unseat(&self, _room: RoomId, _user: UserId, _now: f64) -> Result<Option<StreamParticipant>> {
        Err(StateError::Unavailable)
    }

    fn clear(&self, _room: RoomId, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn renew(&self, _room: RoomId, _until: f64, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

pub struct UnavailableStreamHands;

impl Default for UnavailableStreamHands {
    fn default() -> Self {
        UnavailableStreamHands::new()
    }
}

impl UnavailableStreamHands {
    pub fn new() -> Self {
        UnavailableStreamHands
    }
}

impl StreamHands for UnavailableStreamHands {
    fn raise(&self, _room: RoomId, _user: UserId, _at: f64, _until: f64, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn lower(&self, _room: RoomId, _user: UserId, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn queue(&self, _room: RoomId, _now: f64) -> Result<Vec<i64>> {
        Err(StateError::Unavailable)
    }

    fn clear(&self, _room: RoomId, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn renew(&self, _room: RoomId, _until: f64, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

pub struct UnavailableStreamTally;

impl Default for UnavailableStreamTally {
    fn default() -> Self {
        UnavailableStreamTally::new()
    }
}

impl UnavailableStreamTally {
    pub fn new() -> Self {
        UnavailableStreamTally
    }
}

impl StreamTally for UnavailableStreamTally {
    fn count_reaction(&self, _room: RoomId, _emoji: &str, _until: f64, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn reactions(&self, _room: RoomId, _now: f64) -> Result<BTreeMap<String, u64>> {
        Err(StateError::Unavailable)
    }

    fn raise_peak(&self, _room: RoomId, _seen: u64, _until: f64, _now: f64) -> Result<u64> {
        Err(StateError::Unavailable)
    }

    fn peak(&self, _room: RoomId, _now: f64) -> Result<u64> {
        Err(StateError::Unavailable)
    }

    fn clear(&self, _room: RoomId, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn renew(&self, _room: RoomId, _until: f64, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

pub struct UnavailableStreamDonations;

impl Default for UnavailableStreamDonations {
    fn default() -> Self {
        UnavailableStreamDonations::new()
    }
}

impl UnavailableStreamDonations {
    pub fn new() -> Self {
        UnavailableStreamDonations
    }
}

impl StreamDonations for UnavailableStreamDonations {
    fn add(&self, _room: RoomId, _donation: &Donation, _until: f64, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn list(&self, _room: RoomId, _now: f64) -> Result<Vec<Donation>> {
        Err(StateError::Unavailable)
    }

    fn clear(&self, _room: RoomId, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn renew(&self, _room: RoomId, _until: f64, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::{UnavailableStreamRecords, UnavailableStreamRoster, UnavailableStreamTally};
    use crate::error::StateError;
    use crate::ports::stream_records::StreamRecords;
    use crate::ports::stream_roster::StreamRoster;
    use crate::ports::stream_tally::StreamTally;
    use vortex_core::room::room_id::RoomId;

    fn room() -> RoomId {
        RoomId::of(1).unwrap()
    }

    #[test]
    fn a_stream_that_cannot_be_shared_is_refused_rather_than_kept_for_one_worker() {
        assert_eq!(
            UnavailableStreamRecords::new().find(room(), 1_000.0),
            Err(StateError::Unavailable)
        );
        assert_eq!(
            UnavailableStreamRoster::new().list(room(), 1_000.0),
            Err(StateError::Unavailable)
        );
        assert_eq!(
            UnavailableStreamTally::new().peak(room(), 1_000.0),
            Err(StateError::Unavailable)
        );
    }
}
