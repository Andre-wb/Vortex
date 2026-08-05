//! Параметры запроса: имя -> список значений (аналог `urllib.parse.parse_qs`).

use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParamMap {
    inner: BTreeMap<String, Vec<String>>,
}

impl ParamMap {
    pub fn new() -> Self {
        ParamMap::default()
    }

    pub fn push(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.inner
            .entry(name.into())
            .or_default()
            .push(value.into());
    }

    pub fn get(&self, name: &str) -> Option<&[String]> {
        self.inner.get(name).map(Vec::as_slice)
    }

    /// Пары (имя, значение) — по одной на каждое значение многозначного параметра.
    pub fn flat_iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.inner
            .iter()
            .flat_map(|(name, values)| values.iter().map(move |v| (name.as_str(), v.as_str())))
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::ParamMap;

    #[test]
    fn flattens_multi_valued_params() {
        let mut params = ParamMap::new();
        params.push("id", "1");
        params.push("id", "2");
        let pairs: Vec<_> = params.flat_iter().collect();
        assert_eq!(pairs, vec![("id", "1"), ("id", "2")]);
        assert_eq!(params.len(), 1);
        assert_eq!(params.get("id").map(<[String]>::len), Some(2));
    }
}
