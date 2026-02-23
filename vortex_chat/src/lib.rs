use pyo3::prelude::*;
use pyo3::types::PyBytes;
use blake3;

/// Быстрое хэширование сообщений (для проверки целостности)
#[pyfunction]
fn hash_message(_py: Python<'_>, message: &Bound<'_, PyBytes>) -> PyResult<String> {
    let hash = blake3::hash(message.as_bytes());
    Ok(hash.to_hex().to_string())
}

/// Простое шифрование XOR (для демонстрации)
#[pyfunction]
fn encrypt_message(py: Python<'_>, message: &Bound<'_, PyBytes>, key: u8) -> PyResult<Py<PyBytes>> {
    let bytes = message.as_bytes();
    let encrypted: Vec<u8> = bytes.iter().map(|&b| b ^ key).collect();
    Ok(PyBytes::new(py, &encrypted).into())
}

/// Дешифровка
#[pyfunction]
fn decrypt_message(py: Python<'_>, encrypted: &Bound<'_, PyBytes>, key: u8) -> PyResult<Py<PyBytes>> {
    let bytes = encrypted.as_bytes();
    let decrypted: Vec<u8> = bytes.iter().map(|&b| b ^ key).collect();
    Ok(PyBytes::new(py, &decrypted).into())
}

/// Класс для отслеживания сообщений
#[pyclass]
struct ChatStats {
    message_count: u64,
    bytes_processed: u64,
}

#[pymethods]
impl ChatStats {
    #[new]
    fn new() -> Self {
        ChatStats {
            message_count: 0,
            bytes_processed: 0,
        }
    }

    fn add_message(&mut self, size: usize) {
        self.message_count += 1;
        self.bytes_processed += size as u64;
    }

    fn get_stats(&self) -> String {
        format!("📊 Сообщений: {}, обработано: {} KB",
                self.message_count,
                self.bytes_processed / 1024)
    }
}

/// Регистрируем модуль
#[pymodule]
fn vortex_chat(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hash_message, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_message, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_message, m)?)?;
    m.add_class::<ChatStats>()?;
    m.add("VERSION", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}