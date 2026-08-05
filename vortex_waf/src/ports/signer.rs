//! Подпись и её проверка в постоянном времени.

pub trait Signer: Send + Sync {
    fn sign(&self, payload: &str) -> String;

    /// Сравнение обязано быть устойчивым к атакам по времени.
    fn verify(&self, payload: &str, signature: &str) -> bool;
}
