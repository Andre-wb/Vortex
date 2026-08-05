//! Проверка ответа на капчу.

pub trait ChallengeVerifier: Send + Sync {
    fn verify(&self, challenge_id: &str, answer: &str) -> bool;
}
