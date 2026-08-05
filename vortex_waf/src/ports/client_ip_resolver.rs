//! Определение адреса источника запроса.
//!
//! LSP: реализации взаимозаменяемы — и «только TCP-пир», и «доверенный прокси»
//! всегда возвращают адрес, ни одна не бросает исключений и не требует особого
//! порядка вызова.

use crate::domain::client_ip::ClientIp;
use crate::domain::header_map::HeaderMap;

pub trait ClientIpResolver: Send + Sync {
    fn resolve(&self, peer: Option<&str>, headers: &HeaderMap) -> ClientIp;
}
