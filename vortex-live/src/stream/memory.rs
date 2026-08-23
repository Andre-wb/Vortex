use std::collections::{BTreeMap, HashMap};

use parking_lot::RwLock;
use vortex_auth::account::user_id::UserId;

use crate::error::Result;
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

struct Held<T> {
    until: f64,
    data: T,
}

struct Shelf<T> {
    rooms: RwLock<HashMap<i64, Held<T>>>,
}

impl<T: Default> Shelf<T> {
    fn new() -> Self {
        Shelf {
            rooms: RwLock::new(HashMap::new()),
        }
    }

    fn read<R>(&self, room: RoomId, now: f64, look: impl FnOnce(&T) -> R) -> Option<R> {
        let rooms = self.rooms.read();
        let held = rooms.get(&room.value()).filter(|held| held.until > now)?;
        Some(look(&held.data))
    }

    fn write<R>(&self, room: RoomId, until: f64, now: f64, change: impl FnOnce(&mut T) -> R) -> R {
        let mut rooms = self.rooms.write();
        rooms.retain(|_, held| held.until > now);
        let held = rooms.entry(room.value()).or_insert_with(|| Held {
            until,
            data: T::default(),
        });
        held.until = until;
        change(&mut held.data)
    }

    fn amend<R>(&self, room: RoomId, now: f64, change: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut rooms = self.rooms.write();
        let held = rooms
            .get_mut(&room.value())
            .filter(|held| held.until > now)?;
        Some(change(&mut held.data))
    }

    fn clear(&self, room: RoomId) {
        self.rooms.write().remove(&room.value());
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> bool {
        let mut rooms = self.rooms.write();
        let Some(held) = rooms.get_mut(&room.value()) else {
            return false;
        };
        if held.until <= now {
            return false;
        }
        held.until = until;
        true
    }
}

pub struct MemoryStreamRecords {
    rooms: RwLock<HashMap<i64, Stream>>,
}

impl Default for MemoryStreamRecords {
    fn default() -> Self {
        MemoryStreamRecords::new()
    }
}

impl MemoryStreamRecords {
    pub fn new() -> Self {
        MemoryStreamRecords {
            rooms: RwLock::new(HashMap::new()),
        }
    }
}

impl StreamRecords for MemoryStreamRecords {
    fn open(&self, room: RoomId, stream: &Stream, now: f64) -> Result<bool> {
        let mut rooms = self.rooms.write();
        rooms.retain(|_, kept| kept.alive_at(now));
        if rooms.contains_key(&room.value()) {
            return Ok(false);
        }
        rooms.insert(room.value(), stream.clone());
        Ok(true)
    }

    fn find(&self, room: RoomId, now: f64) -> Result<Option<Stream>> {
        Ok(self
            .rooms
            .read()
            .get(&room.value())
            .filter(|kept| kept.alive_at(now))
            .cloned())
    }

    fn swap(
        &self,
        room: RoomId,
        expected: &Stream,
        replacement: &Stream,
        now: f64,
    ) -> Result<Swapped> {
        let mut rooms = self.rooms.write();
        let Some(kept) = rooms.get(&room.value()).filter(|kept| kept.alive_at(now)) else {
            return Ok(Swapped::Missing);
        };
        if kept != expected {
            return Ok(Swapped::Changed);
        }
        rooms.insert(room.value(), replacement.clone());
        Ok(Swapped::Done)
    }

    fn forget(&self, room: RoomId, now: f64) -> Result<Option<Stream>> {
        Ok(self
            .rooms
            .write()
            .remove(&room.value())
            .filter(|kept| kept.alive_at(now)))
    }
}

pub struct MemoryStreamRoster {
    shelf: Shelf<BTreeMap<i64, StreamParticipant>>,
}

impl Default for MemoryStreamRoster {
    fn default() -> Self {
        MemoryStreamRoster::new()
    }
}

impl MemoryStreamRoster {
    pub fn new() -> Self {
        MemoryStreamRoster {
            shelf: Shelf::new(),
        }
    }
}

impl StreamRoster for MemoryStreamRoster {
    fn seat(
        &self,
        room: RoomId,
        participant: &StreamParticipant,
        until: f64,
        now: f64,
    ) -> Result<Option<StreamParticipant>> {
        Ok(self.shelf.write(room, until, now, |seated| {
            let user_id = participant.person.user_id;
            if let Some(kept) = seated.get(&user_id) {
                return Some(kept.clone());
            }
            seated.insert(user_id, participant.clone());
            None
        }))
    }

    fn find(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<StreamParticipant>> {
        Ok(self
            .shelf
            .read(room, now, |seated| seated.get(&user.value()).cloned())
            .flatten())
    }

    fn list(&self, room: RoomId, now: f64) -> Result<Vec<StreamParticipant>> {
        Ok(self
            .shelf
            .read(room, now, |seated| seated.values().cloned().collect())
            .unwrap_or_default())
    }

    fn swap_member(
        &self,
        room: RoomId,
        user: UserId,
        expected: &StreamParticipant,
        replacement: &StreamParticipant,
        until: f64,
        now: f64,
    ) -> Result<Swapped> {
        let swapped = self
            .shelf
            .amend(room, now, |seated| match seated.get(&user.value()) {
                None => Swapped::Missing,
                Some(kept) if kept != expected => Swapped::Changed,
                Some(_) => {
                    seated.insert(user.value(), replacement.clone());
                    Swapped::Done
                }
            });
        if swapped == Some(Swapped::Done) {
            self.shelf.renew(room, until, now);
        }
        Ok(swapped.unwrap_or(Swapped::Missing))
    }

    fn unseat(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<StreamParticipant>> {
        Ok(self
            .shelf
            .amend(room, now, |seated| seated.remove(&user.value()))
            .flatten())
    }

    fn clear(&self, room: RoomId, _now: f64) -> Result<()> {
        self.shelf.clear(room);
        Ok(())
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        Ok(self.shelf.renew(room, until, now))
    }
}

pub struct MemoryStreamHands {
    shelf: Shelf<Vec<(f64, i64)>>,
}

impl Default for MemoryStreamHands {
    fn default() -> Self {
        MemoryStreamHands::new()
    }
}

impl MemoryStreamHands {
    pub fn new() -> Self {
        MemoryStreamHands {
            shelf: Shelf::new(),
        }
    }
}

impl StreamHands for MemoryStreamHands {
    fn raise(&self, room: RoomId, user: UserId, at: f64, until: f64, now: f64) -> Result<()> {
        self.shelf.write(room, until, now, |queue| {
            if queue.iter().any(|(_, kept)| *kept == user.value()) {
                return;
            }
            queue.push((at, user.value()));
            queue.sort_by(|left, right| {
                left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal)
            });
        });
        Ok(())
    }

    fn lower(&self, room: RoomId, user: UserId, now: f64) -> Result<()> {
        self.shelf.amend(room, now, |queue| {
            queue.retain(|(_, kept)| *kept != user.value());
        });
        Ok(())
    }

    fn queue(&self, room: RoomId, now: f64) -> Result<Vec<i64>> {
        Ok(self
            .shelf
            .read(room, now, |queue| {
                queue.iter().map(|(_, user_id)| *user_id).collect()
            })
            .unwrap_or_default())
    }

    fn clear(&self, room: RoomId, _now: f64) -> Result<()> {
        self.shelf.clear(room);
        Ok(())
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        Ok(self.shelf.renew(room, until, now))
    }
}

#[derive(Default)]
struct Counters {
    reactions: BTreeMap<String, u64>,
    peak: u64,
}

pub struct MemoryStreamTally {
    shelf: Shelf<Counters>,
}

impl Default for MemoryStreamTally {
    fn default() -> Self {
        MemoryStreamTally::new()
    }
}

impl MemoryStreamTally {
    pub fn new() -> Self {
        MemoryStreamTally {
            shelf: Shelf::new(),
        }
    }
}

impl StreamTally for MemoryStreamTally {
    fn count_reaction(&self, room: RoomId, emoji: &str, until: f64, now: f64) -> Result<()> {
        self.shelf.write(room, until, now, |counters| {
            *counters.reactions.entry(emoji.to_owned()).or_insert(0) += 1;
        });
        Ok(())
    }

    fn reactions(&self, room: RoomId, now: f64) -> Result<BTreeMap<String, u64>> {
        Ok(self
            .shelf
            .read(room, now, |counters| counters.reactions.clone())
            .unwrap_or_default())
    }

    fn raise_peak(&self, room: RoomId, seen: u64, until: f64, now: f64) -> Result<u64> {
        Ok(self.shelf.write(room, until, now, |counters| {
            counters.peak = counters.peak.max(seen);
            counters.peak
        }))
    }

    fn peak(&self, room: RoomId, now: f64) -> Result<u64> {
        Ok(self
            .shelf
            .read(room, now, |counters| counters.peak)
            .unwrap_or_default())
    }

    fn clear(&self, room: RoomId, _now: f64) -> Result<()> {
        self.shelf.clear(room);
        Ok(())
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        Ok(self.shelf.renew(room, until, now))
    }
}

pub struct MemoryStreamDonations {
    shelf: Shelf<Vec<Donation>>,
}

impl Default for MemoryStreamDonations {
    fn default() -> Self {
        MemoryStreamDonations::new()
    }
}

impl MemoryStreamDonations {
    pub fn new() -> Self {
        MemoryStreamDonations {
            shelf: Shelf::new(),
        }
    }
}

impl StreamDonations for MemoryStreamDonations {
    fn add(&self, room: RoomId, donation: &Donation, until: f64, now: f64) -> Result<()> {
        self.shelf.write(room, until, now, |log| {
            log.push(donation.clone());
        });
        Ok(())
    }

    fn list(&self, room: RoomId, now: f64) -> Result<Vec<Donation>> {
        Ok(self
            .shelf
            .read(room, now, |log| log.clone())
            .unwrap_or_default())
    }

    fn clear(&self, room: RoomId, _now: f64) -> Result<()> {
        self.shelf.clear(room);
        Ok(())
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        Ok(self.shelf.renew(room, until, now))
    }
}
