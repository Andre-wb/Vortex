use vortex_routing::route::name::RouteName;

pub const HEALTH: &str = "health";
pub const HEALTH_READY: &str = "health-ready";
pub const METRICS: &str = "metrics";

pub fn named(value: &str) -> RouteName {
    RouteName::parse(value).expect("имя роута задано в коде и проходит разбор")
}

#[cfg(test)]
mod tests {
    use super::{named, HEALTH, HEALTH_READY, METRICS};

    #[test]
    fn every_route_of_this_slice_has_a_parsable_name() {
        for value in [HEALTH, HEALTH_READY, METRICS] {
            assert_eq!(named(value).as_str(), value);
        }
    }
}
