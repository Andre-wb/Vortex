//! Инспектор одного аспекта запроса.
//!
//! Каждая реализация проверяет ровно одну вещь: метод, длину URL, заголовок,
//! тело, путь. Движок ничего не знает об их числе и порядке.

use crate::domain::finding::Finding;
use crate::domain::request::InspectedRequest;

pub trait Inspector: Send + Sync {
    /// Имя для журналирования и диагностики.
    fn name(&self) -> &'static str;

    fn inspect(&self, request: &InspectedRequest) -> Vec<Finding>;
}
