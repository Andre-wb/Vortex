use vortex_core::time::moment::Moment;

pub fn wire_stamp(unix_seconds: i64) -> String {
    let moment = Moment::at(unix_seconds);
    format!("{}T{}Z", moment.date.written(), moment.time.written())
}

#[cfg(test)]
mod tests {
    use super::wire_stamp;

    #[test]
    fn a_moment_is_written_with_a_zulu_suffix_and_no_fraction() {
        assert_eq!(wire_stamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(wire_stamp(1_785_834_930), "2026-08-04T09:15:30Z");
    }

    #[test]
    fn a_leap_day_is_written_like_any_other_day() {
        assert_eq!(wire_stamp(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn every_stamp_has_the_same_width() {
        for seconds in [0_i64, 1_000_000_000, 1_785_834_930, 2_147_483_647] {
            assert_eq!(wire_stamp(seconds).len(), 20);
        }
    }
}
