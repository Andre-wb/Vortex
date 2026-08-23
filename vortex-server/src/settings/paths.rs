use std::path::PathBuf;

use crate::settings::environment;

pub const DEFAULT_UPLOAD_DIR: &str = "uploads";
pub const DEFAULT_KEYS_DIR: &str = "keys";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePaths {
    uploads: PathBuf,
    keys: PathBuf,
}

impl Default for NodePaths {
    fn default() -> Self {
        NodePaths::new(DEFAULT_UPLOAD_DIR, DEFAULT_KEYS_DIR)
    }
}

impl NodePaths {
    pub fn new(uploads: impl Into<PathBuf>, keys: impl Into<PathBuf>) -> Self {
        NodePaths {
            uploads: uploads.into(),
            keys: keys.into(),
        }
    }

    pub fn from_environment() -> Self {
        NodePaths::new(
            environment::text_or("UPLOAD_DIR", DEFAULT_UPLOAD_DIR),
            environment::text_or("KEYS_DIR", DEFAULT_KEYS_DIR),
        )
    }

    pub fn uploads(&self) -> &PathBuf {
        &self.uploads
    }

    pub fn keys(&self) -> &PathBuf {
        &self.keys
    }
}

#[cfg(test)]
mod tests {
    use super::{NodePaths, DEFAULT_KEYS_DIR, DEFAULT_UPLOAD_DIR};

    #[test]
    fn the_defaults_match_the_relative_directories_of_the_python_node() {
        let paths = NodePaths::default();
        assert_eq!(paths.uploads().as_os_str(), DEFAULT_UPLOAD_DIR);
        assert_eq!(paths.keys().as_os_str(), DEFAULT_KEYS_DIR);
    }
}
