//! Пути, не проходящие через WAF.
//!
//! В основном это точки потоковой загрузки: их тело буферизовать в память
//! нельзя, и у них есть собственные ограничители.

#[derive(Debug, Clone)]
pub struct ExcludedPaths {
    prefixes: Vec<String>,
}

impl Default for ExcludedPaths {
    fn default() -> Self {
        ExcludedPaths::new([
            "/static/",
            "/health",
            "/favicon.ico",
            "/robots.txt",
            "/waf/stats",
            "/waf/captcha",
            "/waf/test",
            "/api/files/upload-chunk/",
            "/api/files/upload-init",
            "/api/files/upload-complete/",
            "/api/files/upload-cancel/",
            "/api/files/upload-status/",
            "/api/authentication/qr-",
            "/api/bmp/",
            "/api/push-proxy/",
            "/api/authentication/passkey/",
        ])
    }
}

impl ExcludedPaths {
    pub fn new<I, S>(prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        ExcludedPaths {
            prefixes: prefixes
                .into_iter()
                .map(|p| p.as_ref().to_ascii_lowercase())
                .collect(),
        }
    }

    pub fn empty() -> Self {
        ExcludedPaths {
            prefixes: Vec::new(),
        }
    }

    pub fn contains(&self, path: &str) -> bool {
        let lowered = path.to_ascii_lowercase();
        self.prefixes.iter().any(|p| lowered.starts_with(p))
    }

    pub fn add(&mut self, prefix: impl AsRef<str>) {
        self.prefixes.push(prefix.as_ref().to_ascii_lowercase());
    }

    pub fn len(&self) -> usize {
        self.prefixes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::ExcludedPaths;

    #[test]
    fn matches_by_prefix_ignoring_case() {
        let excluded = ExcludedPaths::default();
        assert!(excluded.contains("/api/files/upload-chunk/42"));
        assert!(excluded.contains("/STATIC/app.js"));
        assert!(!excluded.contains("/api/messages"));
    }

    #[test]
    fn link_preview_is_not_excluded() {
        // Внешняя выборка по ссылке — поверхность SSRF, её проверять нужно.
        assert!(!ExcludedPaths::default().contains("/api/link-preview"));
    }

    #[test]
    fn custom_list_replaces_the_default() {
        let mut excluded = ExcludedPaths::empty();
        assert!(!excluded.contains("/health"));
        excluded.add("/health");
        assert!(excluded.contains("/health"));
    }
}
