use crate::cookie::token;
use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;
use crate::time::civil::Date;

pub const ANALYTICS_LOW: u64 = 100_000_000;
pub const ANALYTICS_HIGH: u64 = 999_999_999;
pub const LINKER_LOW: u64 = 100_000;
pub const LINKER_HIGH: u64 = 999_999;
pub const SESSION_AGE: u64 = 86_400;
pub const VISITOR_AGE: u64 = 86_400 * 30;
pub const LINKER_AGE: u64 = 3_600;
pub const CLEARANCE_BYTES: usize = 32;
pub const IDENTITY_BYTES: usize = 48;
pub const IDENTITY_CHANCE: f64 = 0.3;
pub const JAR_CHANCE: f64 = 0.5;
pub const ROTATE_CLEARANCE_CHANCE: f64 = 0.2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieJar {
    visitor: String,
    session: String,
    clearance: String,
    bot_check: String,
}

impl CookieJar {
    pub fn opened(random: &dyn RandomSource, now: i64) -> Self {
        CookieJar {
            visitor: analytics_id(random, now, VISITOR_AGE),
            session: analytics_id(random, now, SESSION_AGE),
            clearance: token::hex(random, CLEARANCE_BYTES),
            bot_check: token::hex(random, CLEARANCE_BYTES),
        }
    }

    pub fn header(&self, random: &dyn RandomSource, now: i64) -> String {
        let mut jar = vec![
            format!("_ga={}", self.visitor),
            format!("_gid={}", self.session),
            "_gat=1".to_owned(),
            format!("cf_clearance={}", self.clearance),
            format!("__cf_bm={}", self.bot_check),
            format!(
                "_gcl_au=1.1.{}.{}",
                token::between(random, LINKER_LOW, LINKER_HIGH),
                now - token::between(random, 0, LINKER_AGE) as i64
            ),
        ];
        if uniform::unit(random) < IDENTITY_CHANCE {
            jar.push(format!("NID={}", token::hex(random, IDENTITY_BYTES)));
        }
        if uniform::unit(random) < JAR_CHANCE {
            let day = Date::at(now);
            jar.push(format!(
                "1P_JAR={}-{:02}",
                day.written(),
                Date::hour_at(now)
            ));
        }
        jar.join("; ")
    }

    pub fn rotate(&mut self, random: &dyn RandomSource, now: i64) {
        self.session = analytics_id(random, now, 0);
        if uniform::unit(random) < ROTATE_CLEARANCE_CHANCE {
            self.clearance = token::hex(random, CLEARANCE_BYTES);
        }
    }
}

fn analytics_id(random: &dyn RandomSource, now: i64, age: u64) -> String {
    format!(
        "GA1.2.{}.{}",
        token::between(random, ANALYTICS_LOW, ANALYTICS_HIGH),
        now - token::between(random, 0, age) as i64
    )
}

#[cfg(test)]
mod tests {
    use super::CookieJar;
    use crate::random::fixed_random::FixedRandom;
    use crate::random::os_random::OsRandom;

    const NOW: i64 = 1_754_611_200;

    fn names(header: &str) -> Vec<&str> {
        header
            .split("; ")
            .map(|pair| pair.split('=').next().unwrap())
            .collect()
    }

    #[test]
    fn a_jar_always_carries_what_a_browser_that_visited_google_carries() {
        let random = OsRandom::new();
        let jar = CookieJar::opened(&random, NOW);
        let header = jar.header(&random, NOW);
        let names = names(&header);
        for expected in ["_ga", "_gid", "_gat", "cf_clearance", "__cf_bm", "_gcl_au"] {
            assert!(names.contains(&expected), "нет {expected}");
        }
    }

    #[test]
    fn the_cookies_that_identify_a_visitor_do_not_change_between_requests() {
        let random = OsRandom::new();
        let jar = CookieJar::opened(&random, NOW);
        let first = jar.header(&random, NOW);
        let second = jar.header(&random, NOW + 60);
        let visitor = |header: &str| {
            header
                .split("; ")
                .find(|pair| pair.starts_with("_ga="))
                .unwrap()
                .to_owned()
        };
        assert_eq!(visitor(&first), visitor(&second));
    }

    #[test]
    fn the_cookies_that_only_sometimes_appear_appear_only_sometimes() {
        let never = FixedRandom::new(vec![]).with_filler(0xFF);
        let always = FixedRandom::new(vec![]).with_filler(0x00);
        let jar = CookieJar::opened(&always, NOW);
        assert!(!names(&jar.header(&never, NOW)).contains(&"NID"));
        assert!(names(&jar.header(&always, NOW)).contains(&"NID"));
        assert!(names(&jar.header(&always, NOW)).contains(&"1P_JAR"));
    }

    #[test]
    fn the_hour_stamp_names_the_hour_it_was_made_in() {
        let always = FixedRandom::new(vec![]).with_filler(0x00);
        let jar = CookieJar::opened(&always, NOW);
        let header = jar.header(&always, NOW + 3600 * 13);
        assert!(header.contains("1P_JAR=2025-08-08-13"), "{header}");
    }

    #[test]
    fn a_visitor_was_first_seen_before_now_and_never_after_it() {
        let random = OsRandom::new();
        for _ in 0..200 {
            let jar = CookieJar::opened(&random, NOW);
            let header = jar.header(&random, NOW);
            for pair in header.split("; ") {
                if let Some(value) = pair.strip_prefix("_ga=GA1.2.") {
                    let stamp: i64 = value.split('.').nth(1).unwrap().parse().unwrap();
                    assert!(stamp <= NOW);
                    assert!(stamp >= NOW - 86_400 * 30);
                }
            }
        }
    }

    #[test]
    fn rotating_a_jar_replaces_the_session_and_keeps_the_visitor() {
        let random = OsRandom::new();
        let mut jar = CookieJar::opened(&random, NOW);
        let before = jar.clone();
        jar.rotate(&random, NOW + 600);
        assert_ne!(jar, before);
        let visitor_of = |jar: &CookieJar| {
            jar.header(&random, NOW)
                .split("; ")
                .next()
                .unwrap()
                .to_owned()
        };
        assert_eq!(visitor_of(&jar), visitor_of(&before));
    }
}
