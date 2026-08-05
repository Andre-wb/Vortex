//! Прогон сигнатур по пути запроса.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::ports::inspector::Inspector;
use crate::scanning::field_scanner::FieldScanner;
use std::sync::Arc;

pub struct PathSignatureInspector {
    scanner: Arc<FieldScanner>,
}

impl PathSignatureInspector {
    pub fn new(scanner: Arc<FieldScanner>) -> Self {
        PathSignatureInspector { scanner }
    }
}

impl Inspector for PathSignatureInspector {
    fn name(&self) -> &'static str {
        "path-signature"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        // Фрагмент значения в находку не кладём: путь и так виден целиком.
        self.scanner.scan_text(&request.path, "URL path", false)
    }
}
