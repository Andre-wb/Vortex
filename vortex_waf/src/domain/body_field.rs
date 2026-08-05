//! Именованное поле тела запроса — общий результат работы всех разборщиков.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyField {
    pub name: String,
    pub value: String,
}

impl BodyField {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        BodyField {
            name: name.into(),
            value: value.into(),
        }
    }
}
