use std::sync::Arc;

use fred::prelude::*;
use vortex_bmp::ports::push_registry::PushRegistry;
use vortex_bmp::push::category::PushCategory;
use vortex_bmp::push::endpoint::PushEndpoint;
use vortex_bmp::push::limits;
use vortex_bmp::push::refusal::{PushStateError, Result};
use vortex_bmp::push::registration::Registration;
use vortex_bmp::push::tally::Tally;
use vortex_bmp::push::token::PushToken;

use crate::backbone::RedisBackbone;
use crate::bmp::scripts::{PUSH_FORGET, PUSH_HOLD, PUSH_READ, PUSH_TALLY};
use crate::keys::KeySpace;

const HELD: &str = "push-held";
const WHERE: &str = "push-where";
const WAKES: &str = "push-wakes";
const BUSY: &str = "push-busy";
const DOMAIN: &str = "bmp";

pub struct RedisPushRegistry {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
    depth: usize,
    lifetime: f64,
}

impl RedisPushRegistry {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        Self::sized(
            backbone,
            limits::MAX_TOKENS_PER_CATEGORY,
            limits::TOKEN_LIFETIME_SECONDS,
        )
    }

    pub fn sized(backbone: Arc<RedisBackbone>, depth: usize, lifetime: f64) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisPushRegistry {
            backbone,
            space,
            depth,
            lifetime,
        }
    }

    fn held_key(&self, category: PushCategory) -> String {
        self.space.member_key(HELD, &category.written())
    }

    fn where_key(&self, category: PushCategory) -> String {
        self.space.member_key(WHERE, &category.written())
    }

    fn wakes_key(&self) -> String {
        self.space.key(WAKES)
    }

    fn busy_key(&self) -> String {
        self.space.key(BUSY)
    }

    fn busy(&self) -> Result<Vec<PushCategory>> {
        let key = self.busy_key();
        let named = self
            .backbone
            .execute(
                "список занятых категорий",
                move |pool| {
                    let key = key.clone();
                    async move { pool.smembers::<Vec<String>, _>(key).await }
                },
            )
            .map_err(|_| PushStateError::Unavailable)?;
        Ok(named
            .iter()
            .filter_map(|one| one.parse::<u8>().ok())
            .map(PushCategory::of)
            .collect())
    }

    fn spread(&self, over: &[PushCategory]) -> Vec<String> {
        let mut keys = Vec::with_capacity(over.len() * 2 + 1);
        for category in over {
            keys.push(self.held_key(*category));
        }
        for category in over {
            keys.push(self.where_key(*category));
        }
        keys
    }
}

impl PushRegistry for RedisPushRegistry {
    fn register(&self, categories: &[PushCategory], registration: &Registration) -> Result<()> {
        if categories.is_empty() {
            return Ok(());
        }
        let mut keys = self.spread(categories);
        keys.push(self.busy_key());

        let named: Vec<String> = categories.iter().map(|one| one.written()).collect();
        let token = registration.token().written().to_owned();
        let endpoint = registration.endpoint().written().to_owned();
        let made_at = registration.registered_at();
        let depth = self.depth as i64;
        let life = self.lifetime.ceil() as i64 + 1;

        self.backbone
            .execute("запись пуш-регистрации", move |pool| {
                let keys = keys.clone();
                let mut args: Vec<Value> = vec![
                    token.clone().into(),
                    endpoint.clone().into(),
                    made_at.into(),
                    depth.into(),
                    life.into(),
                ];
                args.extend(named.iter().map(|one| Value::from(one.clone())));
                async move { PUSH_HOLD.run::<i64>(&pool, keys, args).await }
            })
            .map_err(|_| PushStateError::Unavailable)?;
        Ok(())
    }

    fn unregister(&self, token: &PushToken) -> Result<usize> {
        let busy = self.busy()?;
        if busy.is_empty() {
            return Ok(0);
        }
        let mut keys = self.spread(&busy);
        keys.push(self.busy_key());

        let held = token.written().to_owned();
        let named: Vec<String> = busy.iter().map(|one| one.written()).collect();
        let dropped = self
            .backbone
            .execute(
                "удаление пуш-регистрации",
                move |pool| {
                    let keys = keys.clone();
                    let mut args: Vec<Value> = vec![held.clone().into()];
                    args.extend(named.iter().map(|one| Value::from(one.clone())));
                    async move { PUSH_FORGET.run::<i64>(&pool, keys, args).await }
                },
            )
            .map_err(|_| PushStateError::Unavailable)?;
        Ok(dropped.max(0) as usize)
    }

    fn registrations(&self, category: PushCategory, now: f64) -> Result<Vec<Registration>> {
        let keys = vec![
            self.held_key(category),
            self.where_key(category),
            self.busy_key(),
        ];
        let lifetime = self.lifetime;
        let named = category.written();
        let rows = self
            .backbone
            .execute("чтение пуш-регистраций", move |pool| {
                let keys = keys.clone();
                let args: Vec<Value> = vec![now.into(), lifetime.into(), named.clone().into()];
                async move { PUSH_READ.run::<Vec<String>>(&pool, keys, args).await }
            })
            .map_err(|_| PushStateError::Unavailable)?;
        Ok(registrations_of(&rows))
    }

    fn note_wake(&self) -> Result<u64> {
        let key = self.wakes_key();
        let total = self
            .backbone
            .execute("счёт побудок", move |pool| {
                let key = key.clone();
                async move { pool.incr::<i64, _>(key).await }
            })
            .map_err(|_| PushStateError::Unavailable)?;
        Ok(total.max(0) as u64)
    }

    fn tally(&self) -> Result<Tally> {
        let busy = self.busy()?;
        let mut keys: Vec<String> = busy.iter().map(|one| self.held_key(*one)).collect();
        keys.push(self.busy_key());
        keys.push(self.wakes_key());

        let named: Vec<String> = busy.iter().map(|one| one.written()).collect();
        let counted = self
            .backbone
            .execute("статистика пуш-прокси", move |pool| {
                let keys = keys.clone();
                let args: Vec<Value> = named.iter().map(|one| Value::from(one.clone())).collect();
                async move { PUSH_TALLY.run::<Vec<i64>>(&pool, keys, args).await }
            })
            .map_err(|_| PushStateError::Unavailable)?;

        let tokens = counted.first().copied().unwrap_or_default().max(0) as usize;
        let categories = counted.get(1).copied().unwrap_or_default().max(0) as usize;
        let wakes = counted.get(2).copied().unwrap_or_default().max(0) as u64;
        Ok(Tally::of(tokens, categories, wakes))
    }
}

fn registrations_of(rows: &[String]) -> Vec<Registration> {
    rows.chunks_exact(3)
        .filter_map(|row| {
            let token = PushToken::parse(&row[0]).ok()?;
            let endpoint = PushEndpoint::parse(&row[1]).ok()?;
            let made_at = row[2].parse().ok()?;
            Some(Registration::made(token, endpoint, made_at))
        })
        .collect()
}
