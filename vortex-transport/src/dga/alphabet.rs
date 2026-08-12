pub const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxyz";
pub const VOWELS: &[u8] = b"aeiou";
pub const TLDS: [&str; 7] = [".com", ".net", ".org", ".info", ".xyz", ".online", ".site"];

pub const SHORTEST: usize = 6;
pub const LENGTH_SPREAD: usize = 7;

pub fn letter(position: usize, drawn: u8) -> char {
    let alphabet = if position.is_multiple_of(2) {
        CONSONANTS
    } else {
        VOWELS
    };
    alphabet[drawn as usize % alphabet.len()] as char
}

pub fn tld(drawn: u8) -> &'static str {
    TLDS[drawn as usize % TLDS.len()]
}

pub fn length(drawn: u8) -> usize {
    SHORTEST + drawn as usize % LENGTH_SPREAD
}

#[cfg(test)]
mod tests {
    use super::{length, letter, tld, CONSONANTS, LENGTH_SPREAD, SHORTEST, TLDS, VOWELS};

    #[test]
    fn a_name_alternates_between_letters_that_can_be_pronounced_together() {
        for drawn in 0..=255u8 {
            assert!(CONSONANTS.contains(&(letter(0, drawn) as u8)));
            assert!(VOWELS.contains(&(letter(1, drawn) as u8)));
            assert!(CONSONANTS.contains(&(letter(2, drawn) as u8)));
        }
    }

    #[test]
    fn every_draw_names_a_zone_that_exists() {
        for drawn in 0..=255u8 {
            assert!(TLDS.contains(&tld(drawn)));
        }
    }

    #[test]
    fn a_name_is_never_shorter_or_longer_than_a_domain_should_be() {
        for drawn in 0..=255u8 {
            let counted = length(drawn);
            assert!(counted >= SHORTEST);
            assert!(counted < SHORTEST + LENGTH_SPREAD);
        }
    }

    #[test]
    fn the_alphabets_never_share_a_letter() {
        for letter in CONSONANTS {
            assert!(!VOWELS.contains(letter));
        }
    }
}
