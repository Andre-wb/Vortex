//! Разборщик тела запроса под конкретный content-type.
//!
//! OCP: цепочка `if 'json' … elif 'form' … elif 'multipart'` из прежнего движка
//! заменена реестром реализаций — поддержка нового формата добавляется новым
//! файлом.

use crate::domain::body_field::BodyField;
use crate::domain::content_type::ContentType;
use crate::domain::finding::Finding;

/// Результат разбора.
#[derive(Debug, Clone, Default)]
pub struct ParseOutcome {
    /// Именованные поля, которые далее прогоняются через правила.
    pub fields: Vec<BodyField>,
    /// Находки, специфичные для формата (traversal в multipart и т.п.).
    pub findings: Vec<Finding>,
    /// Признак «тело разобрано». Если `false`, применяется запасной
    /// сплошной скан всего тела — как в прежнем поведении при битом JSON.
    pub consumed: bool,
}

impl ParseOutcome {
    pub fn consumed(fields: Vec<BodyField>, findings: Vec<Finding>) -> Self {
        ParseOutcome {
            fields,
            findings,
            consumed: true,
        }
    }

    /// Разбор не удался: находки отдаём, но запасной скан всё равно нужен.
    pub fn rejected(findings: Vec<Finding>) -> Self {
        ParseOutcome {
            fields: Vec::new(),
            findings,
            consumed: false,
        }
    }
}

pub trait BodyParser: Send + Sync {
    fn name(&self) -> &'static str;

    fn supports(&self, content_type: &ContentType) -> bool;

    fn parse(&self, body: &str) -> ParseOutcome;
}
