use std::sync::Arc;

use vortex_routing::error::RoutingError;
use vortex_routing::flags::absent::AbsentRouteFlags;
use vortex_routing::flags::service::RouteFlagService;
use vortex_routing::handler::decision::Handler;
use vortex_routing::route::name::RouteName;

fn route(value: &str) -> RouteName {
    RouteName::parse(value).unwrap()
}

#[tokio::test]
async fn without_a_flag_store_every_route_still_answers_and_goes_to_python() {
    let service = RouteFlagService::new(Arc::new(AbsentRouteFlags::new()));
    assert_eq!(service.resolve(&route("health")).await, Handler::Python);
    assert_eq!(service.resolve(&route("metrics")).await, Handler::Python);
}

#[tokio::test]
async fn pointing_a_route_without_a_store_is_refused_rather_than_silently_lost() {
    let service = RouteFlagService::new(Arc::new(AbsentRouteFlags::new()));
    assert_eq!(
        service.point(&route("health"), Handler::Rust).await.err(),
        Some(RoutingError::Unavailable)
    );
    assert_eq!(
        service.clear(&route("health")).await.err(),
        Some(RoutingError::Unavailable)
    );
}
