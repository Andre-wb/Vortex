use pyo3::{pyclass, pymethods};

pub mod hash;
pub mod crypt;



/// Класс для отслеживания сообщений
#[pyclass]
pub struct ChatStats {
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