pub const MAX_ATTEMPTS: usize = 32;

pub fn within(low: f64, high: f64, mut draw: impl FnMut() -> f64) -> Option<f64> {
    if low.is_nan() || high.is_nan() || low > high {
        return None;
    }
    for _ in 0..MAX_ATTEMPTS {
        let drawn = draw();
        if drawn >= low && drawn <= high {
            return Some(drawn);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{within, MAX_ATTEMPTS};
    use std::cell::Cell;

    #[test]
    fn a_draw_inside_the_interval_is_taken_as_it_is() {
        assert_eq!(within(0.0, 1.0, || 0.5), Some(0.5));
    }

    #[test]
    fn a_draw_outside_the_interval_is_taken_again_instead_of_being_clamped() {
        let attempt = Cell::new(0);
        let drawn = within(0.0, 1.0, || {
            attempt.set(attempt.get() + 1);
            if attempt.get() < 3 {
                9.0
            } else {
                0.25
            }
        });
        assert_eq!(drawn, Some(0.25));
        assert_eq!(attempt.get(), 3);
    }

    #[test]
    fn the_bounds_themselves_are_inside_the_interval() {
        assert_eq!(within(0.0, 1.0, || 0.0), Some(0.0));
        assert_eq!(within(0.0, 1.0, || 1.0), Some(1.0));
    }

    #[test]
    fn a_draw_that_never_lands_gives_up_instead_of_looping_forever() {
        let attempt = Cell::new(0);
        let drawn = within(0.0, 1.0, || {
            attempt.set(attempt.get() + 1);
            9.0
        });
        assert_eq!(drawn, None);
        assert_eq!(attempt.get(), MAX_ATTEMPTS);
    }

    #[test]
    fn an_interval_that_is_not_an_interval_has_nothing_to_draw_from() {
        assert_eq!(within(1.0, 0.0, || 0.5), None);
        assert_eq!(within(f64::NAN, 1.0, || 0.5), None);
    }
}
