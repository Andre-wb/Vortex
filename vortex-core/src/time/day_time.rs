use crate::time::civil::SECONDS_PER_DAY;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DayTime {
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl DayTime {
    pub fn at(unix_seconds: i64) -> DayTime {
        let seconds = unix_seconds.rem_euclid(SECONDS_PER_DAY);
        DayTime {
            hour: (seconds / 3600) as u32,
            minute: (seconds % 3600 / 60) as u32,
            second: (seconds % 60) as u32,
        }
    }

    pub fn of(hour: u32, minute: u32, second: u32) -> Option<DayTime> {
        if hour > 23 || minute > 59 || second > 60 {
            return None;
        }
        Some(DayTime {
            hour,
            minute,
            second: second.min(59),
        })
    }

    pub fn seconds_of_day(&self) -> i64 {
        (self.hour * 3600 + self.minute * 60 + self.second) as i64
    }

    pub fn written(&self) -> String {
        format!("{:02}:{:02}:{:02}", self.hour, self.minute, self.second)
    }
}

#[cfg(test)]
mod tests {
    use super::DayTime;
    use crate::time::civil::SECONDS_PER_DAY;

    #[test]
    fn midnight_is_the_start_of_the_day() {
        assert_eq!(DayTime::at(0).written(), "00:00:00");
        assert_eq!(DayTime::at(0).seconds_of_day(), 0);
    }

    #[test]
    fn the_last_second_of_the_day_is_still_that_day() {
        assert_eq!(DayTime::at(SECONDS_PER_DAY - 1).written(), "23:59:59");
    }

    #[test]
    fn a_moment_before_the_epoch_reads_from_the_end_of_the_day() {
        assert_eq!(DayTime::at(-1).written(), "23:59:59");
    }

    #[test]
    fn a_time_of_day_survives_a_round_trip() {
        for seconds in [0_i64, 1, 3599, 3600, 45_296, SECONDS_PER_DAY - 1] {
            let time = DayTime::at(seconds);
            assert_eq!(time.seconds_of_day(), seconds);
        }
    }

    #[test]
    fn an_hour_that_the_clock_does_not_have_is_refused() {
        assert_eq!(DayTime::of(24, 0, 0), None);
        assert_eq!(DayTime::of(0, 60, 0), None);
        assert_eq!(DayTime::of(0, 0, 61), None);
    }

    #[test]
    fn a_leap_second_is_read_as_the_last_second_of_the_minute() {
        assert_eq!(DayTime::of(23, 59, 60).unwrap().second, 59);
    }
}
