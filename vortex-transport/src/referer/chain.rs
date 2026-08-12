use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;

pub const SEARCH_ENGINES: [&str; 4] = [
    "https://www.google.com/",
    "https://www.google.ru/",
    "https://yandex.ru/",
    "https://www.bing.com/",
];

pub const SOCIAL: [&str; 3] = [
    "https://t.me/",
    "https://vk.com/",
    "https://www.youtube.com/",
];

pub const PAGES: [&str; 3] = ["/", "/features", "/app"];
pub const RESTART_CHANCE: f64 = 0.3;
pub const DEEPEST_ENTRY: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefererChain {
    site: String,
    steps: Vec<String>,
}

impl RefererChain {
    pub fn starting_at(site: &str, random: &dyn RandomSource) -> Self {
        let mut chain = RefererChain {
            site: site.trim_end_matches('/').to_owned(),
            steps: Vec::new(),
        };
        chain.restart(random);
        chain
    }

    pub fn restart(&mut self, random: &dyn RandomSource) {
        let sources: Vec<&str> = SEARCH_ENGINES
            .iter()
            .chain(SOCIAL.iter())
            .copied()
            .collect();
        let picked = sources[uniform::below(random, sources.len() as u64) as usize];
        self.steps = std::iter::once(picked.to_owned())
            .chain(PAGES.iter().map(|page| format!("{}{}", self.site, page)))
            .collect();
    }

    pub fn referer(&self, depth: usize) -> &str {
        let last = self.steps.len().saturating_sub(1);
        self.steps[depth.min(last)].as_str()
    }

    pub fn entry_referer(&self, random: &dyn RandomSource) -> &str {
        let deepest = (self.steps.len().saturating_sub(1) as u64).min(DEEPEST_ENTRY);
        let depth = if deepest <= 1 {
            deepest
        } else {
            1 + uniform::below(random, deepest)
        };
        self.referer(depth as usize)
    }

    pub fn advance(&mut self, random: &dyn RandomSource) {
        if uniform::unit(random) < RESTART_CHANCE {
            self.restart(random);
        }
    }

    pub fn steps(&self) -> &[String] {
        &self.steps
    }
}

#[cfg(test)]
mod tests {
    use super::{RefererChain, SEARCH_ENGINES, SOCIAL};
    use crate::random::fixed_random::FixedRandom;
    use crate::random::os_random::OsRandom;

    const SITE: &str = "https://vortex.example";

    #[test]
    fn a_visit_starts_somewhere_a_real_visit_could_start() {
        let random = OsRandom::new();
        for _ in 0..200 {
            let chain = RefererChain::starting_at(SITE, &random);
            let source = chain.referer(0);
            assert!(
                SEARCH_ENGINES.contains(&source) || SOCIAL.contains(&source),
                "пришли ниоткуда: {source}"
            );
        }
    }

    #[test]
    fn the_chain_walks_from_the_outside_into_the_site() {
        let random = OsRandom::new();
        let chain = RefererChain::starting_at(SITE, &random);
        assert_eq!(chain.referer(1), "https://vortex.example/");
        assert_eq!(chain.referer(2), "https://vortex.example/features");
        assert_eq!(chain.referer(3), "https://vortex.example/app");
    }

    #[test]
    fn asking_deeper_than_the_chain_goes_gives_its_last_step() {
        let random = OsRandom::new();
        let chain = RefererChain::starting_at(SITE, &random);
        assert_eq!(chain.referer(99), chain.referer(3));
    }

    #[test]
    fn a_visitor_never_arrives_claiming_they_came_from_the_search_engine_itself() {
        let random = OsRandom::new();
        let chain = RefererChain::starting_at(SITE, &random);
        for _ in 0..500 {
            assert_ne!(chain.entry_referer(&random), chain.referer(0));
        }
    }

    #[test]
    fn the_site_is_written_once_however_it_was_given() {
        let random = OsRandom::new();
        let bare = RefererChain::starting_at("https://vortex.example", &random);
        let slashed = RefererChain::starting_at("https://vortex.example/", &random);
        assert_eq!(bare.referer(1), slashed.referer(1));
        assert_eq!(bare.referer(1), "https://vortex.example/");
    }

    #[test]
    fn a_chain_that_is_advanced_sometimes_starts_over_and_sometimes_does_not() {
        let always = FixedRandom::new(vec![]).with_filler(0x00);
        let never = FixedRandom::new(vec![]).with_filler(0xFF);
        let random = OsRandom::new();

        let mut kept = RefererChain::starting_at(SITE, &random);
        let before = kept.clone();
        kept.advance(&never);
        assert_eq!(kept, before);

        let mut restarted = RefererChain::starting_at(SITE, &random);
        restarted.advance(&always);
        assert_eq!(restarted.referer(0), SEARCH_ENGINES[0]);
    }
}
