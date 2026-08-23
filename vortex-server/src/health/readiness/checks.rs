use std::fs;
use std::path::Path;

use crate::settings::paths::NodePaths;

pub const PROBE_FILE: &str = ".healthcheck";
pub const PROBE_CONTENT: &str = "ok";
pub const OK: &str = "ok";
pub const MISSING: &str = "missing";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalChecks {
    pub uploads_dir: String,
    pub keys_dir: String,
}

impl LocalChecks {
    pub fn run(paths: &NodePaths) -> Self {
        LocalChecks {
            uploads_dir: writable(paths.uploads()),
            keys_dir: present(paths.keys()),
        }
    }

    pub fn passed(&self) -> bool {
        self.uploads_dir == OK && self.keys_dir == OK
    }
}

fn writable(directory: &Path) -> String {
    let probe = directory.join(PROBE_FILE);
    match fs::write(&probe, PROBE_CONTENT).and_then(|()| fs::remove_file(&probe)) {
        Ok(()) => OK.to_string(),
        Err(error) => format!("error: {error}"),
    }
}

fn present(directory: &Path) -> String {
    if directory.exists() {
        OK.to_string()
    } else {
        MISSING.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{LocalChecks, MISSING, OK};
    use crate::settings::paths::NodePaths;

    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("vortex-server-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("каталог создаётся");
        directory
    }

    #[test]
    fn a_writable_uploads_directory_and_a_present_keys_directory_pass() {
        let uploads = scratch("passing-uploads");
        let keys = scratch("passing-keys");
        let checks = LocalChecks::run(&NodePaths::new(uploads, keys));
        assert_eq!(checks.uploads_dir, OK);
        assert_eq!(checks.keys_dir, OK);
        assert!(checks.passed());
    }

    #[test]
    fn a_keys_directory_that_does_not_exist_is_reported_missing() {
        let uploads = scratch("missing-keys-uploads");
        let checks = LocalChecks::run(&NodePaths::new(
            uploads,
            std::env::temp_dir().join("vortex-server-нет-такого"),
        ));
        assert_eq!(checks.keys_dir, MISSING);
        assert!(!checks.passed());
    }

    #[test]
    fn an_unwritable_uploads_directory_is_reported_as_an_error() {
        let checks = LocalChecks::run(&NodePaths::new(
            std::env::temp_dir().join("vortex-server-нет-такого"),
            scratch("unwritable-keys"),
        ));
        assert!(checks.uploads_dir.starts_with("error: "));
        assert!(!checks.passed());
    }
}
