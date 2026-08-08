use crate::probe::catalogue::PROBES;

pub const LAST_RESORT: &str = "tor";

pub fn of(blocked: &[&'static str]) -> &'static str {
    PROBES
        .iter()
        .find(|probe| !blocked.contains(&probe.name))
        .map(|probe| probe.name)
        .unwrap_or(LAST_RESORT)
}

#[cfg(test)]
mod tests {
    use super::{of, LAST_RESORT};
    use crate::probe::catalogue::PROBES;

    #[test]
    fn a_region_that_blocks_nothing_gets_the_flagship() {
        assert_eq!(of(&[]), "reality");
    }

    #[test]
    fn the_first_transport_the_region_still_reaches_is_the_one_recommended() {
        assert_eq!(of(&["reality"]), "direct_https");
        assert_eq!(of(&["reality", "direct_https"]), "websocket");
        assert_eq!(of(&["reality", "direct_https", "websocket"]), "sse");
    }

    #[test]
    fn a_region_that_blocks_everything_is_still_told_to_try_the_last_resort() {
        let all: Vec<&'static str> = PROBES.iter().map(|probe| probe.name).collect();
        assert_eq!(of(&all), LAST_RESORT);
    }

    #[test]
    fn the_recommendation_never_names_a_blocked_transport() {
        for skip in 0..PROBES.len() {
            let blocked: Vec<&'static str> =
                PROBES.iter().take(skip).map(|probe| probe.name).collect();
            assert!(!blocked.contains(&of(&blocked)));
        }
    }
}
