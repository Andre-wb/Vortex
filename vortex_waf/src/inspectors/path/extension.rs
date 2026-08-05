//! Опасные расширения в пути запроса.
//!
//! Список шире, чем у проверки загрузок: запрос к `/shell.py` — это попытка
//! выполнить скрипт на сервере, тогда как отправка `.py` вложением законна.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::domain::severity::Severity;
use crate::ports::inspector::Inspector;

pub const DANGEROUS_EXTENSIONS: &[&str] = &[".php", ".asp", ".aspx", ".jsp", ".py", ".pl", ".sh"];

#[derive(Debug, Clone, Copy, Default)]
pub struct PathExtensionInspector;

impl PathExtensionInspector {
    pub fn new() -> Self {
        PathExtensionInspector
    }
}

impl Inspector for PathExtensionInspector {
    fn name(&self) -> &'static str {
        "path-extension"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        let lowered = request.path.to_ascii_lowercase();
        DANGEROUS_EXTENSIONS
            .iter()
            .filter(|ext| lowered.ends_with(**ext))
            .map(|ext| {
                Finding::new("DANGEROUS-EXTENSION", Severity::Medium)
                    .with_description(format!("Dangerous file extension: {ext}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::PathExtensionInspector;
    use crate::domain::request_builder::RequestBuilder;
    use crate::ports::inspector::Inspector;

    #[test]
    fn flags_script_extensions() {
        let req = RequestBuilder::new().path("/admin/Shell.PHP").build();
        assert_eq!(PathExtensionInspector::new().inspect(&req).len(), 1);
    }

    #[test]
    fn ordinary_routes_pass() {
        let req = RequestBuilder::new().path("/api/messages").build();
        assert!(PathExtensionInspector::new().inspect(&req).is_empty());
    }
}
