//! Действие, предписанное правилом при срабатывании.

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    Alert,
    Log,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Block => "block",
            Action::Alert => "alert",
            Action::Log => "log",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
