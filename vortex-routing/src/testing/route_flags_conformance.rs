use std::sync::Arc;

use crate::flags::service::{RouteFlagService, FALLBACK};
use crate::handler::decision::Handler;
use crate::ports::route_flags::RouteFlags;
use crate::route::name::RouteName;

fn route(value: &str) -> RouteName {
    RouteName::parse(value).unwrap()
}

pub async fn an_unpointed_route_goes_to_python(store: Arc<dyn RouteFlags>) {
    let service = RouteFlagService::new(store);
    assert_eq!(service.resolve(&route("health")).await, FALLBACK);
    assert_eq!(FALLBACK, Handler::Python);
}

pub async fn a_route_pointed_at_rust_is_served_by_rust(store: Arc<dyn RouteFlags>) {
    let service = RouteFlagService::new(store);
    service
        .point(&route("health"), Handler::Rust)
        .await
        .unwrap();
    assert_eq!(service.resolve(&route("health")).await, Handler::Rust);
}

pub async fn pointing_back_at_python_takes_effect_without_a_restart(store: Arc<dyn RouteFlags>) {
    let service = RouteFlagService::new(store);
    service
        .point(&route("metrics"), Handler::Rust)
        .await
        .unwrap();
    service
        .point(&route("metrics"), Handler::Python)
        .await
        .unwrap();
    assert_eq!(service.resolve(&route("metrics")).await, Handler::Python);
}

pub async fn clearing_a_route_returns_it_to_the_default(store: Arc<dyn RouteFlags>) {
    let service = RouteFlagService::new(store);
    service
        .point(&route("health-ready"), Handler::Rust)
        .await
        .unwrap();
    assert!(service.clear(&route("health-ready")).await.unwrap());
    assert_eq!(service.resolve(&route("health-ready")).await, FALLBACK);
    assert!(!service.clear(&route("health-ready")).await.unwrap());
}

pub async fn routes_do_not_shadow_each_other(store: Arc<dyn RouteFlags>) {
    let service = RouteFlagService::new(store);
    service
        .point(&route("health"), Handler::Rust)
        .await
        .unwrap();
    service
        .point(&route("metrics"), Handler::Python)
        .await
        .unwrap();
    assert_eq!(service.resolve(&route("health")).await, Handler::Rust);
    assert_eq!(service.resolve(&route("metrics")).await, Handler::Python);
}
