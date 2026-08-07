//! История обращений адреса — счётная часть ограничителя частоты.
//!
//! Отделена от политики (белый список, эскалация в блокировку): при нескольких
//! процессах общей должна быть именно история, а решение по ней принимается
//! одинаково в любом рантайме.

use crate::domain::client_ip::ClientIp;
use crate::domain::timestamp::Timestamp;

pub trait RequestHistory: Send + Sync {
    /// Учесть обращение. `None` — в пределах лимита; `Some((попаданий в окно,
    /// секунд до освобождения))` — лимит исчерпан, обращение не записано.
    fn register(
        &self,
        ip: &ClientIp,
        now: Timestamp,
        requests: usize,
        window_secs: u64,
    ) -> Option<(usize, f64)>;

    fn hits_in_window(&self, ip: &ClientIp, now: Timestamp, window_secs: u64) -> usize;

    /// Удаление истории адресов, у которых в окне ничего не осталось.
    fn forget_stale(&self, now: Timestamp, window_secs: u64) -> usize;

    fn tracked_clients(&self) -> usize;
}
