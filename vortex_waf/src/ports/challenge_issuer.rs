//! Выдача капчи.
//!
//! ISP: выдача и проверка разнесены — фронтовому эндпоинту нужна только выдача,
//! middleware только проверка.

use crate::captcha::challenge::Challenge;
use crate::domain::client_ip::ClientIp;

pub trait ChallengeIssuer: Send + Sync {
    fn issue(&self, client_ip: &ClientIp) -> Challenge;
}
