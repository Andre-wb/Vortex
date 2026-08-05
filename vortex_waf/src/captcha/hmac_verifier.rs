//! Проверка ответа на капчу.

use crate::captcha::token::CaptchaToken;
use crate::ports::challenge_verifier::ChallengeVerifier;
use crate::ports::clock::Clock;
use crate::ports::signer::Signer;
use std::sync::Arc;

pub struct HmacChallengeVerifier {
    signer: Arc<dyn Signer>,
    clock: Arc<dyn Clock>,
}

impl HmacChallengeVerifier {
    pub fn new(signer: Arc<dyn Signer>, clock: Arc<dyn Clock>) -> Self {
        HmacChallengeVerifier { signer, clock }
    }
}

impl ChallengeVerifier for HmacChallengeVerifier {
    fn verify(&self, challenge_id: &str, answer: &str) -> bool {
        let Some(token) = CaptchaToken::decode(challenge_id) else {
            return false;
        };
        if self.clock.now().unix_secs() > token.expires_at {
            return false;
        }
        self.signer.verify(
            &CaptchaToken::payload(answer, token.expires_at),
            &token.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::HmacChallengeVerifier;
    use crate::captcha::arithmetic_issuer::ArithmeticChallengeIssuer;
    use crate::captcha::hmac_signer::HmacSigner;
    use crate::domain::client_ip::ClientIp;
    use crate::ports::challenge_issuer::ChallengeIssuer;
    use crate::ports::challenge_verifier::ChallengeVerifier;
    use crate::random::sequence_random::SequenceRandom;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    fn pair() -> (
        ArithmeticChallengeIssuer,
        HmacChallengeVerifier,
        Arc<ManualClock>,
    ) {
        let signer = Arc::new(HmacSigner::new("общий-секрет"));
        let clock = Arc::new(ManualClock::at_epoch());
        let issuer = ArithmeticChallengeIssuer::new(
            signer.clone(),
            clock.clone(),
            // '+', a = 3, b = 4 -> ответ 7
            Arc::new(SequenceRandom::new(vec![0, 2, 3])),
        );
        let verifier = HmacChallengeVerifier::new(signer, clock.clone());
        (issuer, verifier, clock)
    }

    #[test]
    fn correct_answer_passes() {
        let (issuer, verifier, _) = pair();
        let challenge = issuer.issue(&ClientIp::unknown());
        assert!(verifier.verify(&challenge.challenge_id, "7"));
        assert!(verifier.verify(&challenge.challenge_id, " 7 "));
    }

    #[test]
    fn wrong_answer_fails() {
        let (issuer, verifier, _) = pair();
        let challenge = issuer.issue(&ClientIp::unknown());
        assert!(!verifier.verify(&challenge.challenge_id, "8"));
    }

    #[test]
    fn expired_challenge_fails() {
        let (issuer, verifier, clock) = pair();
        let challenge = issuer.issue(&ClientIp::unknown());
        clock.advance_secs(301);
        assert!(!verifier.verify(&challenge.challenge_id, "7"));
    }

    #[test]
    fn garbage_identifier_fails() {
        let (_, verifier, _) = pair();
        assert!(!verifier.verify("мусор", "7"));
        assert!(!verifier.verify("", "7"));
    }

    #[test]
    fn foreign_secret_fails() {
        let (issuer, _, clock) = pair();
        let challenge = issuer.issue(&ClientIp::unknown());
        let outsider =
            HmacChallengeVerifier::new(Arc::new(HmacSigner::new("другой-секрет")), clock);
        assert!(!outsider.verify(&challenge.challenge_id, "7"));
    }
}
