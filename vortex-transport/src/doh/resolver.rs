pub const PUBLIC: [&str; 5] = [
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/resolve",
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
];

use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct Resolvers {
    endpoints: Vec<String>,
    next: AtomicUsize,
}

impl Default for Resolvers {
    fn default() -> Self {
        Resolvers::of(&PUBLIC)
    }
}

impl Resolvers {
    pub fn of(endpoints: &[&str]) -> Self {
        Resolvers {
            endpoints: endpoints.iter().map(|url| (*url).to_owned()).collect(),
            next: AtomicUsize::new(0),
        }
    }

    pub fn take(&self) -> Option<&str> {
        if self.endpoints.is_empty() {
            return None;
        }
        let at = self.next.fetch_add(1, Ordering::Relaxed) % self.endpoints.len();
        Some(self.endpoints[at].as_str())
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{Resolvers, PUBLIC};

    #[test]
    fn the_resolvers_are_taken_in_turn_and_start_over() {
        let resolvers = Resolvers::of(&["a", "b", "c"]);
        let taken: Vec<&str> = (0..7).map(|_| resolvers.take().unwrap()).collect();
        assert_eq!(taken, vec!["a", "b", "c", "a", "b", "c", "a"]);
    }

    #[test]
    fn no_query_ever_rests_on_one_resolver() {
        assert!(Resolvers::default().len() > 1);
        assert_eq!(Resolvers::default().len(), PUBLIC.len());
    }

    #[test]
    fn a_list_nobody_filled_names_no_resolver() {
        let empty = Resolvers::of(&[]);
        assert!(empty.is_empty());
        assert_eq!(empty.take(), None);
    }

    #[test]
    fn every_resolver_is_reached_over_a_channel_a_censor_cannot_read() {
        for endpoint in PUBLIC {
            assert!(endpoint.starts_with("https://"), "{endpoint}");
        }
    }
}
