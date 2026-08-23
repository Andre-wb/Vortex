use crate::message::limits::CLIENT_STAMP_WINDOW_SECS;
use vortex_core::time::civil::Date;
use vortex_core::time::day_time::DayTime;
use vortex_core::time::moment::Moment;

pub const MICROS_PER_SECOND: i64 = 1_000_000;

pub struct ClientStamp;

impl ClientStamp {
    pub fn read(text: &str) -> Option<i64> {
        let (body, offset_seconds) = split_offset(text)?;
        let (date, rest) = read_date(body)?;
        let (time, microseconds) = read_time(rest)?;
        let seconds = Moment::of(date, time).unix_seconds() - offset_seconds;
        Some(seconds * MICROS_PER_SECOND + microseconds as i64)
    }

    pub fn within_window(text: &str, now_microseconds: i64) -> Option<i64> {
        let stamp = ClientStamp::read(text)?;
        let window = CLIENT_STAMP_WINDOW_SECS * MICROS_PER_SECOND;
        ((now_microseconds - stamp).abs() <= window).then_some(stamp)
    }
}

fn split_offset(text: &str) -> Option<(&str, i64)> {
    if let Some(body) = text.strip_suffix(['Z', 'z']) {
        return Some((body, 0));
    }
    let sign_at = text
        .char_indices()
        .skip(10)
        .find(|(_, character)| *character == '+' || *character == '-')
        .map(|(index, _)| index);
    let Some(index) = sign_at else {
        return Some((text, 0));
    };
    let sign = if text.as_bytes()[index] == b'-' {
        -1
    } else {
        1
    };
    let offset = read_offset(&text[index + 1..])?;
    Some((&text[..index], sign * offset))
}

fn read_offset(text: &str) -> Option<i64> {
    let digits: Vec<u8> = text.bytes().filter(|byte| *byte != b':').collect();
    let (hours, minutes, seconds) = match digits.len() {
        2 => (number(&digits[0..2])?, 0, 0),
        4 => (number(&digits[0..2])?, number(&digits[2..4])?, 0),
        6 => (
            number(&digits[0..2])?,
            number(&digits[2..4])?,
            number(&digits[4..6])?,
        ),
        _ => return None,
    };
    if hours > 23 || minutes > 59 || seconds > 59 {
        return None;
    }
    Some(hours * 3600 + minutes * 60 + seconds)
}

fn read_date(text: &str) -> Option<(Date, &str)> {
    let bytes = text.as_bytes();
    if bytes.len() < 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year = number(&bytes[0..4])?;
    let month = number(&bytes[5..7])? as u32;
    let day = number(&bytes[8..10])? as u32;
    Some((Date::of(year, month, day)?, &text[10..]))
}

fn read_time(text: &str) -> Option<(DayTime, u32)> {
    if text.is_empty() {
        return Some((DayTime::of(0, 0, 0)?, 0));
    }
    let separator = text.chars().next()?;
    if separator != 'T' && separator != 't' && separator != ' ' {
        return None;
    }
    let bytes = &text.as_bytes()[1..];
    if bytes.len() < 5 || bytes[2] != b':' {
        return None;
    }
    let hour = number(&bytes[0..2])? as u32;
    let minute = number(&bytes[3..5])? as u32;
    if bytes.len() == 5 {
        return Some((DayTime::of(hour, minute, 0)?, 0));
    }
    if bytes[5] != b':' || bytes.len() < 8 {
        return None;
    }
    let second = number(&bytes[6..8])? as u32;
    let time = DayTime::of(hour, minute, second)?;
    if bytes.len() == 8 {
        return Some((time, 0));
    }
    if bytes[8] != b'.' && bytes[8] != b',' {
        return None;
    }
    Some((time, read_fraction(&bytes[9..])?))
}

fn read_fraction(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || !digits.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut microseconds = 0u32;
    for position in 0..6 {
        let digit = digits.get(position).map(|byte| byte - b'0').unwrap_or(0);
        microseconds = microseconds * 10 + digit as u32;
    }
    Some(microseconds)
}

fn number(digits: &[u8]) -> Option<i64> {
    if digits.is_empty() || !digits.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(
        digits
            .iter()
            .fold(0i64, |value, byte| value * 10 + (byte - b'0') as i64),
    )
}

#[cfg(test)]
mod tests {
    use super::{ClientStamp, MICROS_PER_SECOND};
    use crate::message::limits::CLIENT_STAMP_WINDOW_SECS;

    const NOON: i64 = 1_785_834_930;

    #[test]
    fn the_shape_the_browser_sends_is_read() {
        assert_eq!(
            ClientStamp::read("2026-08-04T09:15:30.789Z"),
            Some(NOON * MICROS_PER_SECOND + 789_000)
        );
    }

    #[test]
    fn a_stamp_without_a_fraction_is_read() {
        assert_eq!(
            ClientStamp::read("2026-08-04T09:15:30Z"),
            Some(NOON * MICROS_PER_SECOND)
        );
    }

    #[test]
    fn a_stamp_without_a_zone_is_read_as_utc() {
        assert_eq!(
            ClientStamp::read("2026-08-04T09:15:30"),
            Some(NOON * MICROS_PER_SECOND)
        );
    }

    #[test]
    fn an_offset_moves_the_moment_to_utc() {
        assert_eq!(
            ClientStamp::read("2026-08-04T12:15:30+03:00"),
            Some(NOON * MICROS_PER_SECOND)
        );
        assert_eq!(
            ClientStamp::read("2026-08-04T06:15:30-0300"),
            Some(NOON * MICROS_PER_SECOND)
        );
        assert_eq!(
            ClientStamp::read("2026-08-04T12:15:30+03"),
            Some(NOON * MICROS_PER_SECOND)
        );
    }

    #[test]
    fn a_date_alone_is_midnight_of_that_day() {
        assert_eq!(ClientStamp::read("1970-01-01"), Some(0));
        assert_eq!(
            ClientStamp::read("2026-08-04"),
            Some(1_785_801_600 * MICROS_PER_SECOND)
        );
    }

    #[test]
    fn a_space_separates_the_day_from_the_time_as_well() {
        assert_eq!(
            ClientStamp::read("2026-08-04 09:15:30Z"),
            Some(NOON * MICROS_PER_SECOND)
        );
    }

    #[test]
    fn seconds_may_be_left_out() {
        assert_eq!(
            ClientStamp::read("2026-08-04T09:15Z"),
            Some((NOON - 30) * MICROS_PER_SECOND)
        );
    }

    #[test]
    fn a_fraction_is_read_to_the_microsecond_and_no_further() {
        assert_eq!(
            ClientStamp::read("2026-08-04T09:15:30.5Z"),
            Some(NOON * MICROS_PER_SECOND + 500_000)
        );
        assert_eq!(
            ClientStamp::read("2026-08-04T09:15:30.123456789Z"),
            Some(NOON * MICROS_PER_SECOND + 123_456)
        );
    }

    #[test]
    fn a_day_the_calendar_does_not_have_is_not_a_stamp() {
        assert_eq!(ClientStamp::read("2025-02-29T00:00:00Z"), None);
        assert_eq!(ClientStamp::read("2025-13-01T00:00:00Z"), None);
    }

    #[test]
    fn a_malformed_stamp_is_not_a_stamp() {
        for text in [
            "",
            "not a date",
            "2026-08-04X09:15:30Z",
            "20260804T091530Z",
            "2026-8-4T09:15:30Z",
            "2026-08-04T09:15:30.Z",
            "2026-08-04T25:15:30Z",
            "2026-08-04T09:60:30Z",
            "2026-08-04T09:15:30+99:00",
            "2026-08-04T09:15:30+1",
        ] {
            assert_eq!(ClientStamp::read(text), None, "{text}");
        }
    }

    #[test]
    fn a_stamp_inside_the_window_is_accepted() {
        let now = NOON * MICROS_PER_SECOND;
        assert!(ClientStamp::within_window("2026-08-04T09:15:30Z", now).is_some());
        let edge = NOON - CLIENT_STAMP_WINDOW_SECS;
        assert!(
            ClientStamp::within_window("2026-08-04T09:10:30Z", edge * MICROS_PER_SECOND + 1)
                .is_some()
        );
    }

    #[test]
    fn a_stamp_outside_the_window_is_refused() {
        let now = NOON * MICROS_PER_SECOND;
        assert_eq!(
            ClientStamp::within_window("2026-08-04T09:09:00Z", now),
            None
        );
        assert_eq!(
            ClientStamp::within_window("2026-08-04T09:21:00Z", now),
            None
        );
    }

    #[test]
    fn the_window_reaches_the_same_distance_in_both_directions() {
        let now = NOON * MICROS_PER_SECOND;
        let early = (NOON - CLIENT_STAMP_WINDOW_SECS) * MICROS_PER_SECOND;
        let late = (NOON + CLIENT_STAMP_WINDOW_SECS) * MICROS_PER_SECOND;
        assert_eq!(
            ClientStamp::within_window("2026-08-04T09:10:30Z", now),
            Some(early)
        );
        assert_eq!(
            ClientStamp::within_window("2026-08-04T09:20:30Z", now),
            Some(late)
        );
    }
}
