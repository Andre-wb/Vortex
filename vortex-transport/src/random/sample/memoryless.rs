use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;

pub fn delay(base: f64, low: f64, high: f64, random: &dyn RandomSource) -> f64 {
    if !base.is_finite() || base <= 0.0 {
        return 0.0;
    }
    if !low.is_finite() || !high.is_finite() || low < 0.0 || high <= low {
        return base;
    }
    let bottom = (-low).exp();
    let top = (-high).exp();
    let drawn = bottom - uniform::unit(random) * (bottom - top);
    -base * drawn.ln()
}

#[cfg(test)]
mod tests {
    use super::delay;
    use crate::random::fixed_random::FixedRandom;
    use crate::random::os_random::OsRandom;

    #[test]
    fn the_wait_never_leaves_the_interval() {
        let random = OsRandom::new();
        for _ in 0..5000 {
            let waited = delay(300.0, 0.5, 2.0, &random);
            assert!((150.0..=600.0).contains(&waited));
        }
    }

    #[test]
    fn a_zero_draw_is_the_shortest_wait_the_interval_allows() {
        let random = FixedRandom::new(vec![]).with_filler(0x00);
        assert!((delay(300.0, 0.5, 2.0, &random) - 150.0).abs() < 1e-9);
    }

    #[test]
    fn the_largest_draw_stays_inside_the_ceiling() {
        let random = FixedRandom::new(vec![]).with_filler(0xFF);
        let waited = delay(300.0, 0.5, 2.0, &random);
        assert!(waited < 600.0);
        assert!(waited > 599.0);
    }

    #[test]
    fn neither_bound_collects_the_mass_that_was_rejected() {
        let random = OsRandom::new();
        let draws: Vec<f64> = (0..20000)
            .map(|_| delay(300.0, 0.5, 2.0, &random))
            .collect();
        let at_floor = draws.iter().filter(|w| (**w - 150.0).abs() < 1e-9).count();
        let at_ceiling = draws.iter().filter(|w| (**w - 600.0).abs() < 1e-9).count();
        assert_eq!(at_floor, 0, "нижняя граница стала отдельным значением");
        assert_eq!(at_ceiling, 0, "верхняя граница стала отдельным значением");
    }

    #[test]
    fn the_wait_is_not_the_same_twice_in_a_row() {
        let random = OsRandom::new();
        let first = delay(300.0, 0.5, 2.0, &random);
        let second = delay(300.0, 0.5, 2.0, &random);
        assert_ne!(first, second);
    }

    #[test]
    fn an_interval_that_means_nothing_asks_for_no_wait() {
        let random = OsRandom::new();
        assert_eq!(delay(0.0, 0.5, 2.0, &random), 0.0);
        assert_eq!(delay(-1.0, 0.5, 2.0, &random), 0.0);
        assert_eq!(delay(f64::NAN, 0.5, 2.0, &random), 0.0);
    }

    #[test]
    fn a_spread_that_means_nothing_leaves_the_interval_alone() {
        let random = OsRandom::new();
        assert_eq!(delay(300.0, 2.0, 0.5, &random), 300.0);
        assert_eq!(delay(300.0, 0.5, 0.5, &random), 300.0);
        assert_eq!(delay(300.0, -1.0, 2.0, &random), 300.0);
        assert_eq!(delay(300.0, 0.5, f64::INFINITY, &random), 300.0);
    }
}
