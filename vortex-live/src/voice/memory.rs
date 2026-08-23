use std::collections::HashMap;

use parking_lot::RwLock;
use vortex_auth::account::user_id::UserId;

use crate::error::Result;
use crate::ports::voice_presence::VoicePresence;
use crate::voice::joined::Joined;
use crate::voice::participant::Participant;
use crate::voice::patch::MutePatch;
use crate::voice::record::Presence;
use vortex_core::room::room_id::RoomId;

type Channel = HashMap<i64, Presence>;

pub struct MemoryVoicePresence {
    rooms: RwLock<HashMap<i64, Channel>>,
}

impl Default for MemoryVoicePresence {
    fn default() -> Self {
        MemoryVoicePresence::new()
    }
}

impl MemoryVoicePresence {
    pub fn new() -> Self {
        MemoryVoicePresence {
            rooms: RwLock::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.rooms.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub fn ordered(mut kept: Vec<Participant>) -> Vec<Participant> {
    kept.sort_by(|left, right| {
        left.joined_at
            .cmp(&right.joined_at)
            .then(left.user_id.cmp(&right.user_id))
    });
    kept
}

impl VoicePresence for MemoryVoicePresence {
    fn join(&self, room: RoomId, presence: &Presence, now: f64) -> Result<Joined> {
        let mut rooms = self.rooms.write();
        let channel = rooms.entry(room.value()).or_default();
        channel.retain(|_, kept| kept.alive_at(now));
        if let Some(kept) = channel.get(&presence.participant.user_id) {
            return Ok(Joined::Already(kept.participant.clone()));
        }
        channel.insert(presence.participant.user_id, presence.clone());
        Ok(Joined::Fresh(presence.participant.clone()))
    }

    fn leave(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<Participant>> {
        let mut rooms = self.rooms.write();
        let Some(channel) = rooms.get_mut(&room.value()) else {
            return Ok(None);
        };
        let gone = channel
            .remove(&user.value())
            .filter(|kept| kept.alive_at(now))
            .map(|kept| kept.participant);
        if channel.is_empty() {
            rooms.remove(&room.value());
        }
        Ok(gone)
    }

    fn list(&self, room: RoomId, now: f64) -> Result<Vec<Participant>> {
        let rooms = self.rooms.read();
        let Some(channel) = rooms.get(&room.value()) else {
            return Ok(Vec::new());
        };
        Ok(ordered(
            channel
                .values()
                .filter(|kept| kept.alive_at(now))
                .map(|kept| kept.participant.clone())
                .collect(),
        ))
    }

    fn find(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<Participant>> {
        let rooms = self.rooms.read();
        Ok(rooms
            .get(&room.value())
            .and_then(|channel| channel.get(&user.value()))
            .filter(|kept| kept.alive_at(now))
            .map(|kept| kept.participant.clone()))
    }

    fn amend(
        &self,
        room: RoomId,
        user: UserId,
        patch: MutePatch,
        until: f64,
        now: f64,
    ) -> Result<Option<Participant>> {
        let mut rooms = self.rooms.write();
        let Some(channel) = rooms.get_mut(&room.value()) else {
            return Ok(None);
        };
        let Some(kept) = channel.get_mut(&user.value()) else {
            return Ok(None);
        };
        if !kept.alive_at(now) {
            return Ok(None);
        }
        *kept = kept.amended(patch, until);
        Ok(Some(kept.participant.clone()))
    }

    fn renew(&self, room: RoomId, user: UserId, until: f64, now: f64) -> Result<bool> {
        let mut rooms = self.rooms.write();
        let Some(channel) = rooms.get_mut(&room.value()) else {
            return Ok(false);
        };
        let Some(kept) = channel.get_mut(&user.value()) else {
            return Ok(false);
        };
        if !kept.alive_at(now) {
            return Ok(false);
        }
        *kept = kept.renewed(until);
        Ok(true)
    }
}
