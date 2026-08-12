pub const MACHINE_ROUTES: [&str; 5] = [
    "/health",
    "/api/bmp/",
    "/api/federation/",
    "/api/peers/",
    "/api/global/",
];

#[derive(Debug, Clone)]
pub struct ExemptPaths {
    routes: Vec<String>,
}

impl Default for ExemptPaths {
    fn default() -> Self {
        ExemptPaths::of(&MACHINE_ROUTES)
    }
}

impl ExemptPaths {
    pub fn of(routes: &[&str]) -> Self {
        ExemptPaths {
            routes: routes.iter().map(|route| (*route).to_owned()).collect(),
        }
    }

    pub fn none() -> Self {
        ExemptPaths { routes: Vec::new() }
    }

    pub fn covers(&self, path: &str) -> bool {
        self.routes.iter().any(|route| covers_one(route, path))
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

fn covers_one(route: &str, path: &str) -> bool {
    if route.ends_with('/') {
        return path.starts_with(route);
    }
    path == route
}

#[cfg(test)]
mod tests {
    use super::ExemptPaths;

    #[test]
    fn the_route_a_remote_node_probes_is_never_read_as_a_censor_probe() {
        let exempt = ExemptPaths::default();
        assert!(exempt.covers("/health"));
        assert!(exempt.covers("/api/federation/handshake"));
        assert!(exempt.covers("/api/peers/receive"));
        assert!(exempt.covers("/api/global/bootstrap"));
    }

    #[test]
    fn the_mailbox_routes_keep_the_exemption_they_already_had() {
        let exempt = ExemptPaths::default();
        assert!(exempt.covers("/api/bmp/deposit"));
        assert!(exempt.covers("/api/bmp/fast-batch"));
    }

    #[test]
    fn an_exact_route_does_not_cover_the_paths_written_below_it() {
        let exempt = ExemptPaths::default();
        assert!(!exempt.covers("/healthcheck"));
        assert!(!exempt.covers("/health/../admin"));
        assert!(!exempt.covers("/health/deep"));
    }

    #[test]
    fn an_ordinary_route_is_not_exempt() {
        let exempt = ExemptPaths::default();
        assert!(!exempt.covers("/"));
        assert!(!exempt.covers("/api/chats"));
        assert!(!exempt.covers("/static/js/app.js"));
    }

    #[test]
    fn a_detector_told_to_exempt_nothing_exempts_nothing() {
        let exempt = ExemptPaths::none();
        assert!(exempt.is_empty());
        assert!(!exempt.covers("/health"));
    }
}
