pub fn bucket(timestamp: f64, width_secs: u64) -> f64 {
    if width_secs == 0 || !timestamp.is_finite() || timestamp <= 0.0 {
        return timestamp.max(0.0);
    }
    let seconds = timestamp as u64;
    (seconds / width_secs * width_secs) as f64
}

#[cfg(test)]
mod tests {
    use super::bucket;

    #[test]
    fn a_timestamp_is_rounded_down_to_the_window() {
        assert_eq!(bucket(1_700_000_123.75, 300), 1_700_000_100.0);
        assert_eq!(bucket(299.0, 300), 0.0);
        assert_eq!(bucket(300.0, 300), 300.0);
    }

    #[test]
    fn neighbouring_deposits_inside_one_window_are_indistinguishable() {
        assert_eq!(bucket(1_700_000_000.0, 300), bucket(1_700_000_099.0, 300));
    }

    #[test]
    fn a_degenerate_window_leaves_the_timestamp_alone() {
        assert_eq!(bucket(1234.5, 0), 1234.5);
    }

    #[test]
    fn a_timestamp_before_the_epoch_never_becomes_a_huge_number() {
        assert_eq!(bucket(-5.0, 300), 0.0);
        assert_eq!(bucket(f64::NAN, 300), 0.0);
    }
}
