use crate::call::call_id::CallId;
use crate::call::record::Call;
use crate::error::{Result, StateError};
use crate::ports::call_index::CallIndex;
use crate::ports::call_records::CallRecords;
use crate::ports::ring_claims::RingClaims;
use crate::store::swapped::Swapped;
use vortex_core::room::room_id::RoomId;

pub struct UnavailableCallRecords;

impl Default for UnavailableCallRecords {
    fn default() -> Self {
        UnavailableCallRecords::new()
    }
}

impl UnavailableCallRecords {
    pub fn new() -> Self {
        UnavailableCallRecords
    }
}

impl CallRecords for UnavailableCallRecords {
    fn open(&self, _call: &Call, _now: f64) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _call: &CallId, _now: f64) -> Result<Option<Call>> {
        Err(StateError::Unavailable)
    }

    fn swap(
        &self,
        _call: &CallId,
        _expected: &Call,
        _replacement: &Call,
        _now: f64,
    ) -> Result<Swapped> {
        Err(StateError::Unavailable)
    }

    fn forget(&self, _call: &CallId, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

pub struct UnavailableCallIndex;

impl Default for UnavailableCallIndex {
    fn default() -> Self {
        UnavailableCallIndex::new()
    }
}

impl UnavailableCallIndex {
    pub fn new() -> Self {
        UnavailableCallIndex
    }
}

impl CallIndex for UnavailableCallIndex {
    fn claim(
        &self,
        _room: RoomId,
        _call: &CallId,
        _until: f64,
        _now: f64,
    ) -> Result<Option<CallId>> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _room: RoomId, _now: f64) -> Result<Option<CallId>> {
        Err(StateError::Unavailable)
    }

    fn release(&self, _room: RoomId, _call: &CallId, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }

    fn renew(&self, _room: RoomId, _until: f64, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

pub struct UnavailableRingClaims;

impl Default for UnavailableRingClaims {
    fn default() -> Self {
        UnavailableRingClaims::new()
    }
}

impl UnavailableRingClaims {
    pub fn new() -> Self {
        UnavailableRingClaims
    }
}

impl RingClaims for UnavailableRingClaims {
    fn claim(&self, _call: &CallId, _until: f64, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::{UnavailableCallIndex, UnavailableCallRecords, UnavailableRingClaims};
    use crate::call::call_id::CallId;
    use crate::error::StateError;
    use crate::ports::call_index::CallIndex;
    use crate::ports::call_records::CallRecords;
    use crate::ports::ring_claims::RingClaims;
    use vortex_core::room::room_id::RoomId;

    fn call() -> CallId {
        CallId::parse("abcd").unwrap()
    }

    #[test]
    fn a_call_that_cannot_be_shared_is_refused_rather_than_kept_for_one_worker() {
        assert_eq!(
            UnavailableCallRecords::new().find(&call(), 1_000.0),
            Err(StateError::Unavailable)
        );
        assert_eq!(
            UnavailableCallIndex::new().find(RoomId::of(1).unwrap(), 1_000.0),
            Err(StateError::Unavailable)
        );
    }

    #[test]
    fn a_ring_nobody_can_claim_is_never_claimed_by_this_worker() {
        assert_eq!(
            UnavailableRingClaims::new().claim(&call(), 1_030.0, 1_000.0),
            Err(StateError::Unavailable)
        );
    }
}
