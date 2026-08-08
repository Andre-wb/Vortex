use crate::obfuscation::cover::headers::COVER_HEADERS;
use crate::obfuscation::padding::config::PaddingConfig;
use crate::obfuscation::padding::{envelope, size};
use crate::obfuscation::timing::config::DelayConfig;
use crate::obfuscation::timing::{delay, interval};
use crate::ports::random_source::RandomSource;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Obfuscation {
    padding: PaddingConfig,
    delay: DelayConfig,
}

impl Obfuscation {
    pub fn new(padding: PaddingConfig, delay: DelayConfig) -> Self {
        Obfuscation { padding, delay }
    }

    pub fn padding_config(&self) -> &PaddingConfig {
        &self.padding
    }

    pub fn delay_config(&self) -> &DelayConfig {
        &self.delay
    }

    pub fn pad(
        &self,
        data: &[u8],
        targets: Option<&[usize]>,
        random: &dyn RandomSource,
    ) -> Option<Vec<u8>> {
        let pad_len = match targets {
            Some(targets) if !targets.is_empty() => {
                size::for_target(data.len(), targets, &self.padding, random)
            }
            _ => size::choose(&self.padding, random),
        };
        self.pad_with(data, &random.bytes(pad_len))
    }

    pub fn pad_with(&self, data: &[u8], padding: &[u8]) -> Option<Vec<u8>> {
        envelope::pad(data, padding)
    }

    pub fn unpad<'a>(&self, envelope: &'a [u8]) -> Option<&'a [u8]> {
        envelope::unpad(envelope)
    }

    pub fn delay(&self, random: &dyn RandomSource) -> f64 {
        delay::sample(&self.delay, random)
    }

    pub fn is_worth_waiting(&self, seconds: f64) -> bool {
        delay::is_worth_waiting(&self.delay, seconds)
    }

    pub fn interval(&self, base: f64, jitter_ratio: f64, random: &dyn RandomSource) -> f64 {
        interval::randomize(base, jitter_ratio, random)
    }

    pub fn cover_headers(&self) -> &'static [(&'static str, &'static str)] {
        &COVER_HEADERS
    }
}

#[cfg(test)]
mod tests {
    use super::Obfuscation;
    use crate::obfuscation::padding::header::{HEADER_LEN, MAX_FIELD};
    use crate::obfuscation::padding::web_sizes::WEB_SIZES;
    use crate::random::os_random::OsRandom;

    #[test]
    fn what_the_guard_pads_the_guard_reads_back() {
        let guard = Obfuscation::default();
        let random = OsRandom::new();
        let envelope = guard.pad(b"Hello, Vortex!", None, &random).unwrap();
        assert_eq!(guard.unpad(&envelope), Some(&b"Hello, Vortex!"[..]));
    }

    #[test]
    fn a_padded_message_is_always_longer_than_the_message() {
        let guard = Obfuscation::default();
        let random = OsRandom::new();
        for _ in 0..200 {
            let envelope = guard.pad(b"body", None, &random).unwrap();
            assert!(envelope.len() >= 4 + HEADER_LEN + guard.padding_config().min);
        }
    }

    #[test]
    fn a_message_that_does_not_fit_the_format_is_refused_and_not_passed_through() {
        let guard = Obfuscation::default();
        let random = OsRandom::new();
        assert!(guard
            .pad(&vec![0x41; MAX_FIELD + 1], None, &random)
            .is_none());
    }

    #[test]
    fn asking_for_a_web_size_lands_on_that_size_exactly() {
        let guard = Obfuscation::default();
        let random = OsRandom::new();
        for _ in 0..50 {
            let envelope = guard.pad(b"body", Some(&WEB_SIZES), &random).unwrap();
            assert_eq!(envelope.len(), 256);
        }
    }

    #[test]
    fn an_empty_list_of_targets_is_the_same_as_no_targets() {
        let guard = Obfuscation::default();
        let random = OsRandom::new();
        let envelope = guard.pad(b"body", Some(&[]), &random).unwrap();
        let length = envelope.len() - HEADER_LEN - 4;
        assert!((guard.padding_config().min..=guard.padding_config().max).contains(&length));
    }

    #[test]
    fn two_padded_copies_of_one_message_rarely_have_the_same_length() {
        let guard = Obfuscation::default();
        let random = OsRandom::new();
        let lengths: Vec<usize> = (0..200)
            .map(|_| guard.pad(b"body", None, &random).unwrap().len())
            .collect();
        let mut unique = lengths.clone();
        unique.sort_unstable();
        unique.dedup();
        assert!(unique.len() > 50, "длина конверта предсказуема");
    }

    #[test]
    fn the_cover_story_is_the_one_frozen_in_the_crate() {
        let guard = Obfuscation::default();
        assert_eq!(guard.cover_headers().len(), 3);
    }
}
