use crate::probe::catalogue::PROBES;
use crate::probe::entry::Probe;
use crate::probe::kind::{ProbeKind, HEALTH_PATH, SSE_PATH, TOKEN_PATH_PREFIX, WEBSOCKET_PATH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub name: &'static str,
    pub path: String,
    pub accepted: Vec<u16>,
    pub accept_header: Option<&'static str>,
}

pub fn of(probe: &Probe) -> Target {
    Target {
        name: probe.name,
        path: path_of(probe),
        accepted: probe.kind.accepted().to_vec(),
        accept_header: probe.kind.accept_header(),
    }
}

pub fn all() -> Vec<Target> {
    PROBES.iter().map(of).collect()
}

fn path_of(probe: &Probe) -> String {
    match probe.kind {
        ProbeKind::Health => HEALTH_PATH.to_owned(),
        ProbeKind::WebSocket => WEBSOCKET_PATH.to_owned(),
        ProbeKind::Sse => SSE_PATH.to_owned(),
        ProbeKind::Token => format!("{TOKEN_PATH_PREFIX}{}", probe.token().to_hex()),
    }
}

#[cfg(test)]
mod tests {
    use super::{all, of};
    use crate::probe::catalogue::by_name;

    #[test]
    fn a_token_probe_asks_for_the_path_its_own_token_names() {
        let target = of(by_name("reality").unwrap());
        assert_eq!(target.path, "/api/transport/probe/d7ac1d220e6a");
        assert_eq!(target.accepted, vec![200]);
    }

    #[test]
    fn the_reachability_checks_keep_their_own_paths() {
        assert_eq!(of(by_name("direct_https").unwrap()).path, "/health");
        assert_eq!(of(by_name("websocket").unwrap()).path, "/ws/chat/0");
        assert_eq!(
            of(by_name("sse").unwrap()).path,
            "/api/transport/sse/stream"
        );
    }

    #[test]
    fn every_transport_asks_for_a_path_of_its_own() {
        let mut paths: Vec<String> = all().into_iter().map(|target| target.path).collect();
        let before = paths.len();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), before);
    }

    #[test]
    fn a_plan_names_every_transport_the_catalogue_knows() {
        assert_eq!(all().len(), crate::probe::catalogue::PROBES.len());
    }

    #[test]
    fn the_stream_probe_carries_the_header_a_stream_is_asked_for_with() {
        assert_eq!(
            of(by_name("sse").unwrap()).accept_header,
            Some("text/event-stream")
        );
        assert_eq!(of(by_name("reality").unwrap()).accept_header, None);
    }
}
