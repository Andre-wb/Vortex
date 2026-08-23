use std::collections::HashMap;

use parking_lot::RwLock;

use crate::call::call_id::CallId;
use crate::call::record::Call;
use crate::error::Result;
use crate::ports::call_index::CallIndex;
use crate::ports::call_records::CallRecords;
use crate::ports::ring_claims::RingClaims;
use crate::store::swapped::Swapped;
use vortex_core::room::room_id::RoomId;

pub struct MemoryCallRecords {
    calls: RwLock<HashMap<String, Call>>,
}

impl Default for MemoryCallRecords {
    fn default() -> Self {
        MemoryCallRecords::new()
    }
}

impl MemoryCallRecords {
    pub fn new() -> Self {
        MemoryCallRecords {
            calls: RwLock::new(HashMap::new()),
        }
    }
}

impl CallRecords for MemoryCallRecords {
    fn open(&self, call: &Call, now: f64) -> Result<()> {
        let mut calls = self.calls.write();
        calls.retain(|_, kept| kept.until > now);
        calls.insert(call.call_id.clone(), call.clone());
        Ok(())
    }

    fn find(&self, call: &CallId, now: f64) -> Result<Option<Call>> {
        Ok(self
            .calls
            .read()
            .get(call.as_str())
            .filter(|kept| kept.until > now)
            .cloned())
    }

    fn swap(
        &self,
        call: &CallId,
        expected: &Call,
        replacement: &Call,
        now: f64,
    ) -> Result<Swapped> {
        let mut calls = self.calls.write();
        let Some(kept) = calls.get(call.as_str()).filter(|kept| kept.until > now) else {
            return Ok(Swapped::Missing);
        };
        if kept != expected {
            return Ok(Swapped::Changed);
        }
        calls.insert(call.as_str().to_owned(), replacement.clone());
        Ok(Swapped::Done)
    }

    fn forget(&self, call: &CallId, now: f64) -> Result<bool> {
        Ok(self
            .calls
            .write()
            .remove(call.as_str())
            .is_some_and(|kept| kept.until > now))
    }
}

struct Claimed {
    call: String,
    until: f64,
}

pub struct MemoryCallIndex {
    rooms: RwLock<HashMap<i64, Claimed>>,
}

impl Default for MemoryCallIndex {
    fn default() -> Self {
        MemoryCallIndex::new()
    }
}

impl MemoryCallIndex {
    pub fn new() -> Self {
        MemoryCallIndex {
            rooms: RwLock::new(HashMap::new()),
        }
    }
}

impl CallIndex for MemoryCallIndex {
    fn claim(&self, room: RoomId, call: &CallId, until: f64, now: f64) -> Result<Option<CallId>> {
        let mut rooms = self.rooms.write();
        rooms.retain(|_, kept| kept.until > now);
        if let Some(kept) = rooms.get(&room.value()) {
            return Ok(CallId::parse(&kept.call).ok());
        }
        rooms.insert(
            room.value(),
            Claimed {
                call: call.as_str().to_owned(),
                until,
            },
        );
        Ok(None)
    }

    fn find(&self, room: RoomId, now: f64) -> Result<Option<CallId>> {
        Ok(self
            .rooms
            .read()
            .get(&room.value())
            .filter(|kept| kept.until > now)
            .and_then(|kept| CallId::parse(&kept.call).ok()))
    }

    fn release(&self, room: RoomId, call: &CallId, now: f64) -> Result<bool> {
        let mut rooms = self.rooms.write();
        let held = rooms.get(&room.value()).filter(|kept| kept.until > now);
        if held.is_none_or(|kept| kept.call != call.as_str()) {
            return Ok(false);
        }
        rooms.remove(&room.value());
        Ok(true)
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        let mut rooms = self.rooms.write();
        let Some(kept) = rooms.get_mut(&room.value()) else {
            return Ok(false);
        };
        if kept.until <= now {
            return Ok(false);
        }
        kept.until = until;
        Ok(true)
    }
}

pub struct MemoryRingClaims {
    rung: RwLock<HashMap<String, f64>>,
}

impl Default for MemoryRingClaims {
    fn default() -> Self {
        MemoryRingClaims::new()
    }
}

impl MemoryRingClaims {
    pub fn new() -> Self {
        MemoryRingClaims {
            rung: RwLock::new(HashMap::new()),
        }
    }
}

impl RingClaims for MemoryRingClaims {
    fn claim(&self, call: &CallId, until: f64, now: f64) -> Result<bool> {
        let mut rung = self.rung.write();
        rung.retain(|_, kept| *kept > now);
        if rung.contains_key(call.as_str()) {
            return Ok(false);
        }
        rung.insert(call.as_str().to_owned(), until);
        Ok(true)
    }
}
