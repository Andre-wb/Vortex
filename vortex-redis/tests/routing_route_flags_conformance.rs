mod support;

use std::sync::Arc;

use vortex_redis::routing::route_flags::RedisRouteFlags;
use vortex_redis::runtime;
use vortex_routing::testing::route_flags_conformance as agreed;

use support::{backbone, unique_prefix};

#[test]
fn redis_keeps_per_route_flags_the_agreed_way() {
    let Some(shared) = backbone(&unique_prefix("routing-flags")) else {
        return;
    };
    runtime::block_on(async {
        agreed::an_unpointed_route_goes_to_python(Arc::new(RedisRouteFlags::new(shared.clone())))
            .await;
        agreed::a_route_pointed_at_rust_is_served_by_rust(Arc::new(RedisRouteFlags::new(
            shared.clone(),
        )))
        .await;
        agreed::pointing_back_at_python_takes_effect_without_a_restart(Arc::new(
            RedisRouteFlags::new(shared.clone()),
        ))
        .await;
        agreed::clearing_a_route_returns_it_to_the_default(Arc::new(RedisRouteFlags::new(
            shared.clone(),
        )))
        .await;
        agreed::routes_do_not_shadow_each_other(Arc::new(RedisRouteFlags::new(shared))).await;
    });
}
