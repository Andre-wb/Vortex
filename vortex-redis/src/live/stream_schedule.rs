use std::sync::Arc;

use fred::prelude::*;
use vortex_core::room::room_id::RoomId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::stream_schedule::StreamSchedule;
use vortex_live::stream::schedule::entry::ScheduleEntry;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left, CLAIM_DUE, PLAN, UNPLAN};

const DUE: &str = "stream-schedule";
const PLANS: &str = "stream-plans";

pub struct RedisStreamSchedule {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisStreamSchedule {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisStreamSchedule { backbone, space }
    }

    fn due_key(&self) -> String {
        self.space.key(DUE)
    }

    fn plans_key(&self) -> String {
        self.space.key(PLANS)
    }
}

impl StreamSchedule for RedisStreamSchedule {
    fn put(&self, room: RoomId, entry: &ScheduleEntry, until: f64, now: f64) -> Result<()> {
        let due = self.due_key();
        let plans = self.plans_key();
        let member = room.written();
        let wire = entry.to_wire();
        let at = entry.at;
        let life = seconds_left(until, now);
        self.backbone
            .execute("план трансляции", move |pool| {
                let due = due.clone();
                let plans = plans.clone();
                let member = member.clone();
                let wire = wire.clone();
                async move {
                    PLAN.run::<i64>(
                        &pool,
                        vec![due, plans],
                        vec![at.into(), member.into(), wire.into(), life.into()],
                    )
                    .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn find(&self, room: RoomId, _now: f64) -> Result<Option<ScheduleEntry>> {
        let plans = self.plans_key();
        let member = room.written();
        let stored = self
            .backbone
            .execute("чтение плана трансляции", move |pool| {
                let plans = plans.clone();
                let member = member.clone();
                async move { pool.hget::<Option<String>, _, _>(plans, member).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(stored.as_deref().and_then(ScheduleEntry::parse))
    }

    fn forget(&self, room: RoomId, _now: f64) -> Result<bool> {
        let due = self.due_key();
        let plans = self.plans_key();
        let member = room.written();
        let removed = self
            .backbone
            .execute("отмена плана трансляции", move |pool| {
                let due = due.clone();
                let plans = plans.clone();
                let member = member.clone();
                async move {
                    UNPLAN
                        .run::<i64>(&pool, vec![due, plans], vec![member.into()])
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(removed > 0)
    }

    fn claim_due(&self, now: f64) -> Result<Option<ScheduleEntry>> {
        let due = self.due_key();
        let plans = self.plans_key();
        let moment = now.floor() as i64;
        let claimed = self
            .backbone
            .execute(
                "захват наступившего плана трансляции",
                move |pool| {
                    let due = due.clone();
                    let plans = plans.clone();
                    async move {
                        CLAIM_DUE
                            .run::<String>(&pool, vec![due, plans], vec![moment.into()])
                            .await
                    }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        if claimed == scripts::NOTHING {
            return Ok(None);
        }
        Ok(ScheduleEntry::parse(&claimed))
    }
}
