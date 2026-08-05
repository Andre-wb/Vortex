//! Выдача арифметической капчи.

use crate::captcha::challenge::Challenge;
use crate::captcha::token::CaptchaToken;
use crate::domain::client_ip::ClientIp;
use crate::ports::challenge_issuer::ChallengeIssuer;
use crate::ports::clock::Clock;
use crate::ports::random_source::RandomSource;
use crate::ports::signer::Signer;
use std::sync::Arc;

/// Срок жизни задачи в секундах.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// Длина случайного префикса идентификатора в байтах.
const NONCE_BYTES: usize = 8;

const OPERATORS: [char; 3] = ['+', '-', '*'];

pub struct ArithmeticChallengeIssuer {
    signer: Arc<dyn Signer>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn RandomSource>,
    ttl_secs: u64,
}

impl ArithmeticChallengeIssuer {
    pub fn new(
        signer: Arc<dyn Signer>,
        clock: Arc<dyn Clock>,
        random: Arc<dyn RandomSource>,
    ) -> Self {
        ArithmeticChallengeIssuer {
            signer,
            clock,
            random,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    pub fn with_ttl(mut self, ttl_secs: u64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }
}

impl ChallengeIssuer for ArithmeticChallengeIssuer {
    fn issue(&self, _client_ip: &ClientIp) -> Challenge {
        let operator = OPERATORS[self.random.below(OPERATORS.len() as u32) as usize];
        let a = self.random.below(10) as i64 + 1;
        let b = self.random.below(10) as i64 + 1;
        let answer = match operator {
            '+' => a + b,
            '-' => a - b,
            _ => a * b,
        };

        let expires_at = self.clock.now().unix_secs() + self.ttl_secs as i64;
        let signature = self
            .signer
            .sign(&CaptchaToken::payload(&answer.to_string(), expires_at));
        let token = CaptchaToken::new(self.random.hex(NONCE_BYTES), expires_at, signature);

        Challenge::new(
            token.encode(),
            format!("What is {a} {operator} {b}?"),
            self.ttl_secs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ArithmeticChallengeIssuer;
    use crate::captcha::hmac_signer::HmacSigner;
    use crate::captcha::token::CaptchaToken;
    use crate::domain::client_ip::ClientIp;
    use crate::ports::challenge_issuer::ChallengeIssuer;
    use crate::ports::clock::Clock;
    use crate::ports::signer::Signer;
    use crate::random::sequence_random::SequenceRandom;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    #[test]
    fn issued_challenge_is_self_describing() {
        // Последовательность: оператор '+', a = 2+1, b = 3+1.
        let random = Arc::new(SequenceRandom::new(vec![0, 2, 3]));
        let signer = Arc::new(HmacSigner::new("секрет"));
        let clock = Arc::new(ManualClock::at_epoch());
        let issuer = ArithmeticChallengeIssuer::new(signer.clone(), clock.clone(), random);

        let challenge = issuer.issue(&ClientIp::from("1.2.3.4"));
        assert_eq!(challenge.question, "What is 3 + 4?");
        assert_eq!(challenge.expires_in, 300);

        let token = CaptchaToken::decode(&challenge.challenge_id).unwrap();
        assert_eq!(token.expires_at, clock.now().unix_secs() + 300);
        assert!(signer.verify(
            &CaptchaToken::payload("7", token.expires_at),
            &token.signature
        ));
    }

    #[test]
    fn ttl_is_configurable() {
        let issuer = ArithmeticChallengeIssuer::new(
            Arc::new(HmacSigner::new("s")),
            Arc::new(ManualClock::at_epoch()),
            Arc::new(SequenceRandom::new(vec![1])),
        )
        .with_ttl(30);
        assert_eq!(issuer.issue(&ClientIp::unknown()).expires_in, 30);
    }
}
