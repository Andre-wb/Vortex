use crate::ports::random_source::RandomSource;

pub const SALT_LEN: usize = 7;

pub type Salt = [u8; SALT_LEN];

pub fn generate(random: &dyn RandomSource) -> Salt {
    let mut salt = [0u8; SALT_LEN];
    random.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::{generate, SALT_LEN};
    use crate::random::fixed_random::FixedRandom;

    #[test]
    fn takes_its_bytes_from_the_random_source() {
        let random = FixedRandom::new(vec![1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(generate(&random), [1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(SALT_LEN, 7);
    }
}
