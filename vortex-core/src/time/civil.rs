pub const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: i64,
    pub month: u32,
    pub day: u32,
}

impl Date {
    pub fn at(unix_seconds: i64) -> Date {
        from_days(unix_seconds.div_euclid(SECONDS_PER_DAY))
    }

    pub fn hour_at(unix_seconds: i64) -> u32 {
        (unix_seconds.rem_euclid(SECONDS_PER_DAY) / 3600) as u32
    }

    pub fn of(year: i64, month: u32, day: u32) -> Option<Date> {
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        Some(Date { year, month, day })
    }

    pub fn days_since_epoch(&self) -> i64 {
        to_days(self)
    }

    pub fn midnight(&self) -> i64 {
        self.days_since_epoch() * SECONDS_PER_DAY
    }

    pub fn written(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

pub fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

pub fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn from_days(days: i64) -> Date {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    Date {
        year: if month <= 2 { year + 1 } else { year },
        month,
        day,
    }
}

fn to_days(date: &Date) -> i64 {
    let year = if date.month <= 2 {
        date.year - 1
    } else {
        date.year
    };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = date.month as i64;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + date.day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::{days_in_month, is_leap, Date, SECONDS_PER_DAY};

    #[test]
    fn the_epoch_is_the_first_day_of_nineteen_seventy() {
        assert_eq!(Date::at(0).written(), "1970-01-01");
        assert_eq!(Date::hour_at(0), 0);
    }

    #[test]
    fn a_known_moment_is_written_the_way_the_calendar_writes_it() {
        assert_eq!(Date::at(1_754_611_200).written(), "2025-08-08");
        assert_eq!(Date::at(1_000_000_000).written(), "2001-09-09");
        assert_eq!(Date::at(2_147_483_647).written(), "2038-01-19");
    }

    #[test]
    fn a_leap_day_is_a_day_like_any_other() {
        assert_eq!(Date::at(951_782_400).written(), "2000-02-29");
        assert_eq!(Date::at(1_709_164_800).written(), "2024-02-29");
    }

    #[test]
    fn the_day_turns_over_at_midnight_and_not_before_it() {
        let midnight = 1_754_611_200;
        assert_eq!(Date::at(midnight - 1).written(), "2025-08-07");
        assert_eq!(Date::at(midnight).written(), "2025-08-08");
        assert_eq!(Date::hour_at(midnight + 3600 * 13), 13);
    }

    #[test]
    fn a_moment_before_the_epoch_still_names_a_day() {
        assert_eq!(Date::at(-1).written(), "1969-12-31");
        assert_eq!(Date::hour_at(-1), 23);
        assert_eq!(Date::at(-SECONDS_PER_DAY).written(), "1969-12-31");
    }

    #[test]
    fn tomorrow_is_the_next_day_across_every_boundary() {
        for moment in [951_782_400_i64, 1_735_689_599, 1_754_611_200, 0] {
            let today = Date::at(moment);
            let tomorrow = Date::at(moment + SECONDS_PER_DAY);
            assert_ne!(today, tomorrow);
            assert!(tomorrow > today);
        }
    }

    #[test]
    fn a_day_read_back_is_the_day_that_was_written() {
        for moment in [
            0_i64,
            -1,
            951_782_400,
            1_000_000_000,
            1_754_611_200,
            2_147_483_647,
        ] {
            let date = Date::at(moment);
            assert_eq!(date.midnight(), moment - moment.rem_euclid(SECONDS_PER_DAY));
            assert_eq!(Date::at(date.midnight()), date);
        }
    }

    #[test]
    fn a_day_that_the_calendar_does_not_have_is_refused() {
        assert_eq!(Date::of(2025, 2, 29), None);
        assert_eq!(Date::of(2025, 13, 1), None);
        assert_eq!(Date::of(2025, 0, 1), None);
        assert_eq!(Date::of(2025, 4, 31), None);
        assert_eq!(Date::of(2025, 1, 0), None);
    }

    #[test]
    fn a_leap_day_is_accepted_only_in_a_leap_year() {
        assert!(Date::of(2024, 2, 29).is_some());
        assert!(Date::of(2000, 2, 29).is_some());
        assert_eq!(Date::of(1900, 2, 29), None);
        assert!(is_leap(2000));
        assert!(!is_leap(1900));
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2023, 2), 28);
    }

    #[test]
    fn a_named_day_lands_on_the_moment_it_names() {
        assert_eq!(Date::of(1970, 1, 1).unwrap().midnight(), 0);
        assert_eq!(Date::of(2025, 8, 8).unwrap().midnight(), 1_754_611_200);
        assert_eq!(Date::of(1969, 12, 31).unwrap().midnight(), -SECONDS_PER_DAY);
    }
}
