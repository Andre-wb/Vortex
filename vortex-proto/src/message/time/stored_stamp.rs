use vortex_core::time::moment::Moment;

pub fn stored_stamp(unix_seconds: i64, microseconds: u32) -> String {
    let moment = Moment::at(unix_seconds);
    let written = format!("{}T{}", moment.date.written(), moment.time.written());
    if microseconds == 0 {
        written
    } else {
        format!("{written}.{microseconds:06}")
    }
}

#[cfg(test)]
mod tests {
    use super::stored_stamp;

    #[test]
    fn a_whole_second_is_written_without_a_fraction() {
        assert_eq!(stored_stamp(1_785_834_930, 0), "2026-08-04T09:15:30");
    }

    #[test]
    fn a_fraction_is_written_with_six_digits() {
        assert_eq!(stored_stamp(1_785_834_930, 5), "2026-08-04T09:15:30.000005");
        assert_eq!(
            stored_stamp(1_785_834_930, 789_012),
            "2026-08-04T09:15:30.789012"
        );
    }

    #[test]
    fn a_stored_stamp_carries_no_zone_suffix() {
        assert!(!stored_stamp(0, 0).ends_with('Z'));
        assert_eq!(stored_stamp(0, 0), "1970-01-01T00:00:00");
    }
}
