//! Источник случайности.
//!
//! Вынесен в порт, чтобы в тестах капчи и идентификаторов запросов можно было
//! подставить детерминированную реализацию.

pub trait RandomSource: Send + Sync {
    /// Случайное число в диапазоне `[0, upper)`.
    fn below(&self, upper: u32) -> u32;

    fn fill_bytes(&self, buffer: &mut [u8]);

    /// Шестнадцатеричная строка из `n` байт (`2 * n` символов).
    fn hex(&self, n: usize) -> String {
        let mut buf = vec![0u8; n];
        self.fill_bytes(&mut buf);
        hex::encode(buf)
    }
}
