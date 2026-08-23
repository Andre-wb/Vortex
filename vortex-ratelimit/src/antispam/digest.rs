use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(String);

impl Digest {
    pub fn of(text: &str) -> Self {
        let normalised = text.trim().to_lowercase();
        Digest(hex::encode(Sha256::digest(normalised.as_bytes())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Digest;

    #[test]
    fn one_text_always_gives_one_digest() {
        assert_eq!(Digest::of("Привет"), Digest::of("Привет"));
    }

    #[test]
    fn surrounding_space_and_letter_case_never_make_a_new_message() {
        assert_eq!(Digest::of("  Stop  "), Digest::of("stop"));
        assert_eq!(Digest::of("STOP"), Digest::of("stop"));
    }

    #[test]
    fn two_different_texts_are_two_digests() {
        assert_ne!(Digest::of("stop"), Digest::of("start"));
    }

    #[test]
    fn a_digest_carries_no_separator_of_its_own() {
        let digest = Digest::of("a:b:c");
        assert_eq!(digest.as_str().len(), 64);
        assert!(!digest.as_str().contains(':'));
    }
}
