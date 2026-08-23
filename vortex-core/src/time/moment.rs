use crate::time::civil::Date;
use crate::time::day_time::DayTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Moment {
    pub date: Date,
    pub time: DayTime,
}

impl Moment {
    pub fn at(unix_seconds: i64) -> Moment {
        Moment {
            date: Date::at(unix_seconds),
            time: DayTime::at(unix_seconds),
        }
    }

    pub fn of(date: Date, time: DayTime) -> Moment {
        Moment { date, time }
    }

    pub fn unix_seconds(&self) -> i64 {
        self.date.midnight() + self.time.seconds_of_day()
    }
}

#[cfg(test)]
mod tests {
    use super::Moment;
    use crate::time::civil::Date;
    use crate::time::day_time::DayTime;

    #[test]
    fn the_epoch_is_midnight_of_its_first_day() {
        let moment = Moment::at(0);
        assert_eq!(moment.date.written(), "1970-01-01");
        assert_eq!(moment.time.written(), "00:00:00");
        assert_eq!(moment.unix_seconds(), 0);
    }

    #[test]
    fn a_moment_survives_a_round_trip() {
        for seconds in [0_i64, -1, 1_754_611_200, 1_785_834_930, 2_147_483_647] {
            assert_eq!(Moment::at(seconds).unix_seconds(), seconds);
        }
    }

    #[test]
    fn a_named_moment_lands_where_it_is_named() {
        let moment = Moment::of(
            Date::of(2026, 8, 4).unwrap(),
            DayTime::of(9, 15, 30).unwrap(),
        );
        assert_eq!(moment.unix_seconds(), 1_785_834_930);
    }
}
