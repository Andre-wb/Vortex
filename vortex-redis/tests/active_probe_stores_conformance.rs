mod support;

use std::sync::Arc;

use vortex_redis::transport::probe_roll::RedisRoll;
use vortex_redis::transport::probe_sightings::RedisSightings;
use vortex_transport::ports::probe_roll::ProbeRoll;
use vortex_transport::ports::probe_sightings::ProbeSightings;
use vortex_transport::testing::{probe_roll_conformance, probe_sightings_conformance};

#[test]
fn the_redis_sightings_satisfy_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("sightings-probe")).is_none() {
        eprintln!("Redis недоступен — проверка кэша отпечатков пропущена");
        return;
    }
    let make = |room: usize, memory: f64| -> Arc<dyn ProbeSightings> {
        let prefix = support::unique_prefix("sightings");
        Arc::new(RedisSightings::with_limits(
            support::backbone(&prefix).unwrap(),
            room,
            memory,
        ))
    };
    probe_sightings_conformance::check_all(&make);
}

#[test]
fn the_redis_roll_satisfies_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("roll-probe")).is_none() {
        eprintln!("Redis недоступен — проверка списка зондов пропущена");
        return;
    }
    let make = |room: usize, memory: f64| -> Arc<dyn ProbeRoll> {
        let prefix = support::unique_prefix("roll");
        Arc::new(RedisRoll::with_limits(
            support::backbone(&prefix).unwrap(),
            room,
            memory,
        ))
    };
    probe_roll_conformance::check_all(&make);
}
