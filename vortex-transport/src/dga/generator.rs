use crate::dga::alphabet;
use crate::time::civil::{Date, SECONDS_PER_DAY};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const DEFAULT_COUNT: usize = 5;

pub struct DomainGenerator {
    seed: Vec<u8>,
}

impl DomainGenerator {
    pub fn seeded(seed: &str) -> Self {
        DomainGenerator {
            seed: seed.as_bytes().to_vec(),
        }
    }

    pub fn on(&self, day: &str, count: usize) -> Vec<String> {
        (0..count).map(|index| self.one(day, index)).collect()
    }

    pub fn one(&self, day: &str, index: usize) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.seed).expect("HMAC принимает любой ключ");
        mac.update(format!("{day}:{index}").as_bytes());
        named(&mac.finalize().into_bytes())
    }

    pub fn current(&self, now: i64, count: usize) -> Vec<String> {
        let today = Date::at(now).written();
        let tomorrow = Date::at(now + SECONDS_PER_DAY).written();
        let mut domains = self.on(&today, count);
        domains.extend(self.on(&tomorrow, count));
        domains
    }
}

fn named(digest: &[u8]) -> String {
    let length = alphabet::length(digest[0]);
    let mut name = String::with_capacity(length + 6);
    for position in 0..length {
        name.push(alphabet::letter(
            position,
            digest[(position + 1) % digest.len()],
        ));
    }
    name.push_str(alphabet::tld(digest[digest.len() - 1]));
    name
}

#[cfg(test)]
mod tests {
    use super::{DomainGenerator, DEFAULT_COUNT};
    use crate::dga::alphabet::TLDS;

    const SEED: &str = "vortex-mesh-2026";
    const NOON: i64 = 1_754_654_400;

    #[test]
    fn the_same_seed_and_the_same_day_give_the_same_domains_to_everyone() {
        let first = DomainGenerator::seeded(SEED);
        let second = DomainGenerator::seeded(SEED);
        assert_eq!(first.on("2026-08-08", 10), second.on("2026-08-08", 10));
    }

    #[test]
    fn a_different_seed_gives_different_domains() {
        let ours = DomainGenerator::seeded(SEED);
        let theirs = DomainGenerator::seeded("someone-else");
        assert_ne!(ours.on("2026-08-08", 10), theirs.on("2026-08-08", 10));
    }

    #[test]
    fn a_different_day_gives_different_domains() {
        let generator = DomainGenerator::seeded(SEED);
        assert_ne!(generator.on("2026-08-08", 5), generator.on("2026-08-09", 5));
    }

    #[test]
    fn every_domain_is_a_name_and_a_zone_that_exist() {
        let generator = DomainGenerator::seeded(SEED);
        for domain in generator.on("2026-08-08", 50) {
            let zone = TLDS
                .iter()
                .find(|tld| domain.ends_with(*tld))
                .unwrap_or_else(|| panic!("нет зоны у {domain}"));
            let name = &domain[..domain.len() - zone.len()];
            assert!((6..13).contains(&name.len()), "{domain}");
            assert!(name.chars().all(|c| c.is_ascii_lowercase()), "{domain}");
        }
    }

    #[test]
    fn asking_for_more_domains_extends_the_list_and_does_not_rewrite_it() {
        let generator = DomainGenerator::seeded(SEED);
        let few = generator.on("2026-08-08", 3);
        let many = generator.on("2026-08-08", 10);
        assert_eq!(many[..3], few[..]);
    }

    #[test]
    fn the_current_domains_cover_today_and_tomorrow() {
        let generator = DomainGenerator::seeded(SEED);
        let current = generator.current(NOON, DEFAULT_COUNT);
        assert_eq!(current.len(), DEFAULT_COUNT * 2);
        assert_eq!(
            current[..DEFAULT_COUNT],
            generator.on("2025-08-08", DEFAULT_COUNT)[..]
        );
        assert_eq!(
            current[DEFAULT_COUNT..],
            generator.on("2025-08-09", DEFAULT_COUNT)[..]
        );
    }

    #[test]
    fn a_client_and_a_server_in_two_time_zones_still_agree_on_the_day() {
        let generator = DomainGenerator::seeded(SEED);
        let midnight_utc = 1_754_611_200;
        assert_eq!(
            generator.current(midnight_utc, 1),
            generator.current(midnight_utc + 3600 * 11, 1)
        );
    }

    #[test]
    fn the_generated_domains_are_frozen() {
        let generator = DomainGenerator::seeded(SEED);
        assert_eq!(
            generator.on("2026-08-08", 3),
            vec!["musohapepu.net", "wokosiyuqig.com", "wasuwemix.com"]
        );
    }
}
