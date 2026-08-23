use vortex_core::time::civil::Date;
use vortex_core::time::day_time::DayTime;

const MICROS_PER_SECOND: i64 = 1_000_000;
const ZONE: &str = "+00:00";

pub fn written(unix_seconds: f64) -> String {
    let (seconds, microseconds) = split(unix_seconds);
    render(seconds, microseconds)
}

pub fn render(unix_seconds: i64, microseconds: u32) -> String {
    let date = Date::at(unix_seconds).written();
    let time = DayTime::at(unix_seconds).written();
    if microseconds == 0 {
        return format!("{date}T{time}{ZONE}");
    }
    format!("{date}T{time}.{microseconds:06}{ZONE}")
}

pub fn split(unix_seconds: f64) -> (i64, u32) {
    if !unix_seconds.is_finite() {
        return (0, 0);
    }
    let seconds = unix_seconds.floor();
    let mut whole = seconds as i64;
    let mut micros = ((unix_seconds - seconds) * MICROS_PER_SECOND as f64).round() as i64;
    if micros >= MICROS_PER_SECOND {
        whole += 1;
        micros -= MICROS_PER_SECOND;
    }
    (whole, micros as u32)
}

#[cfg(test)]
mod tests {
    use super::{render, split, written};

    #[test]
    fn a_moment_is_printed_the_way_the_room_already_sees_it() {
        assert_eq!(
            render(1_785_834_930, 123_456),
            "2026-08-04T09:15:30.123456+00:00"
        );
    }

    #[test]
    fn a_whole_second_carries_no_fraction_at_all() {
        assert_eq!(render(1_785_834_930, 0), "2026-08-04T09:15:30+00:00");
    }

    #[test]
    fn a_fraction_shorter_than_six_digits_keeps_its_leading_zeros() {
        assert_eq!(render(0, 7), "1970-01-01T00:00:00.000007+00:00");
    }

    #[test]
    fn a_reading_of_the_clock_splits_into_seconds_and_microseconds() {
        assert_eq!(split(1_000.5), (1_000, 500_000));
        assert_eq!(split(1_000.0), (1_000, 0));
    }

    #[test]
    fn a_fraction_that_rounds_up_to_a_whole_second_carries_over() {
        assert_eq!(split(1_000.9999999), (1_001, 0));
    }

    #[test]
    fn a_reading_that_is_not_a_number_prints_the_epoch() {
        assert_eq!(split(f64::NAN), (0, 0));
        assert_eq!(written(f64::INFINITY), "1970-01-01T00:00:00+00:00");
    }
}
