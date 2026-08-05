//! Список параметров, которые правила не проверяют.
//!
//! Токены CSRF по своей природе выглядят как случайный мусор и регулярно
//! ложно срабатывают на сигнатурах.

use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct SafeParams {
    names: HashSet<String>,
}

impl Default for SafeParams {
    fn default() -> Self {
        SafeParams::new(["csrf_token", "_csrf", "csrfmiddlewaretoken"])
    }
}

impl SafeParams {
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        SafeParams {
            names: names
                .into_iter()
                .map(|n| n.as_ref().to_ascii_lowercase())
                .collect(),
        }
    }

    pub fn empty() -> Self {
        SafeParams {
            names: HashSet::new(),
        }
    }

    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(&name.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::SafeParams;

    #[test]
    fn default_covers_csrf_token_names() {
        let safe = SafeParams::default();
        assert!(safe.contains("CSRF_Token"));
        assert!(safe.contains("_csrf"));
        assert!(!safe.contains("comment"));
        assert_eq!(safe.len(), 3);
    }
}
