pub fn epoch_at(timestamp: f64, jitter_secs: u16, period_secs: u64) -> i64 {
    if period_secs == 0 {
        return 0;
    }
    let adjusted = timestamp - f64::from(jitter_secs);
    (adjusted / period_secs as f64) as i64
}

pub fn epoch_span(epoch: i64, skew_epochs: i64) -> impl Iterator<Item = u64> {
    let skew = skew_epochs.max(0);
    (epoch.saturating_sub(skew)..=epoch.saturating_add(skew))
        .map(|candidate| candidate.max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::{epoch_at, epoch_span};

    #[test]
    fn an_hour_of_wall_clock_advances_one_epoch() {
        assert_eq!(epoch_at(3600.0, 0, 3600), 1);
        assert_eq!(epoch_at(7199.0, 0, 3600), 1);
        assert_eq!(epoch_at(7200.0, 0, 3600), 2);
    }

    #[test]
    fn the_jitter_delays_the_rotation_for_this_pair() {
        assert_eq!(epoch_at(3600.0, 600, 3600), 0);
        assert_eq!(epoch_at(4200.0, 600, 3600), 1);
    }

    #[test]
    fn a_timestamp_below_the_jitter_never_yields_a_negative_epoch_in_the_span() {
        assert_eq!(epoch_at(1.0, 600, 3600), 0);
        assert_eq!(epoch_span(0, 1).collect::<Vec<_>>(), vec![0, 0, 1]);
    }

    #[test]
    fn the_span_covers_one_epoch_on_each_side() {
        assert_eq!(epoch_span(10, 1).collect::<Vec<_>>(), vec![9, 10, 11]);
        assert_eq!(epoch_span(10, 0).collect::<Vec<_>>(), vec![10]);
    }

    #[test]
    fn extreme_timestamps_do_not_overflow_the_span() {
        assert_eq!(epoch_at(f64::MAX, 0, 3600), i64::MAX);
        assert_eq!(
            epoch_span(i64::MAX, 1).collect::<Vec<_>>(),
            vec![(i64::MAX - 1) as u64, i64::MAX as u64]
        );
    }
}
