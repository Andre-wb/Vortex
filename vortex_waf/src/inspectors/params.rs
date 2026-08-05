//! Проверка параметров строки запроса.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;
use crate::ports::inspector::Inspector;
use crate::scanning::field_scanner::FieldScanner;
use std::sync::Arc;

pub struct ParamsInspector {
    scanner: Arc<FieldScanner>,
}

impl ParamsInspector {
    pub fn new(scanner: Arc<FieldScanner>) -> Self {
        ParamsInspector { scanner }
    }
}

impl Inspector for ParamsInspector {
    fn name(&self) -> &'static str {
        "params"
    }

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (name, value) in request.params.flat_iter() {
            findings.extend(self.scanner.scan_parameter(name, value));
        }
        findings
    }
}
