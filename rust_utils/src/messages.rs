use pyo3::{pyclass, pymethods};

pub mod crypt;
pub mod hash;

#[pyclass]
pub struct ChatStats {
    message_count: u64,
    bytes_processed: u64,
}

impl Default for ChatStats {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl ChatStats {
    #[new]
    pub fn new() -> Self {
        ChatStats {
            message_count: 0,
            bytes_processed: 0,
        }
    }

    pub fn add_message(&mut self, size: usize) {
        self.message_count += 1;
        self.bytes_processed += size as u64;
    }

    pub fn get_stats(&self) -> String {
        format!(
            "Сообщений: {}, обработано: {} KB",
            self.message_count,
            self.bytes_processed / 1024
        )
    }
}
