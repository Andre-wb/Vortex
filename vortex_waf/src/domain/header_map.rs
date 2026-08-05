//! Заголовки запроса с нормализованными в нижний регистр именами.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderMap {
    inner: BTreeMap<String, String>,
}

impl HeaderMap {
    pub fn new() -> Self {
        HeaderMap::default()
    }

    pub fn insert(&mut self, name: impl AsRef<str>, value: impl Into<String>) {
        self.inner
            .insert(name.as_ref().to_ascii_lowercase(), value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.inner
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.inner.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<K, V> FromIterator<(K, V)> for HeaderMap
where
    K: AsRef<str>,
    V: Into<String>,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = HeaderMap::new();
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::HeaderMap;

    #[test]
    fn lookup_is_case_insensitive() {
        let map: HeaderMap = [("Content-Type", "application/json")].into_iter().collect();
        assert_eq!(map.get("content-type"), Some("application/json"));
        assert_eq!(map.get("CONTENT-TYPE"), Some("application/json"));
        assert!(map.contains("Content-Type"));
        assert_eq!(map.len(), 1);
    }
}
