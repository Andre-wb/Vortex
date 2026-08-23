use std::sync::Arc;

use vortex_routing::flags::memory::MemoryRouteFlags;
use vortex_routing::testing::route_flags_conformance as agreed;

#[tokio::test]
async fn the_process_memory_store_follows_the_agreed_contract() {
    agreed::an_unpointed_route_goes_to_python(Arc::new(MemoryRouteFlags::new())).await;
    agreed::a_route_pointed_at_rust_is_served_by_rust(Arc::new(MemoryRouteFlags::new())).await;
    agreed::pointing_back_at_python_takes_effect_without_a_restart(Arc::new(
        MemoryRouteFlags::new(),
    ))
    .await;
    agreed::clearing_a_route_returns_it_to_the_default(Arc::new(MemoryRouteFlags::new())).await;
    agreed::routes_do_not_shadow_each_other(Arc::new(MemoryRouteFlags::new())).await;
}
