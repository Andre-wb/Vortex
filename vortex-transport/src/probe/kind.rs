pub const HEALTH_PATH: &str = "/health";
pub const WEBSOCKET_PATH: &str = "/ws/chat/0";
pub const SSE_PATH: &str = "/api/transport/sse/stream";
pub const TOKEN_PATH_PREFIX: &str = "/api/transport/probe/";

const EVENT_STREAM: &str = "text/event-stream";

const REACHED_OVER_HTTP: &[u16] = &[200, 401, 403];
const REACHED_OVER_WEBSOCKET: &[u16] = &[101, 200, 401, 403, 426];
const REACHED_OVER_TOKEN: &[u16] = &[200];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    Health,
    WebSocket,
    Sse,
    Token,
}

impl ProbeKind {
    pub fn accepted(&self) -> &'static [u16] {
        match self {
            ProbeKind::Health | ProbeKind::Sse => REACHED_OVER_HTTP,
            ProbeKind::WebSocket => REACHED_OVER_WEBSOCKET,
            ProbeKind::Token => REACHED_OVER_TOKEN,
        }
    }

    pub fn accepts(&self, status: u16) -> bool {
        self.accepted().contains(&status)
    }

    pub fn accept_header(&self) -> Option<&'static str> {
        match self {
            ProbeKind::Sse => Some(EVENT_STREAM),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProbeKind;

    #[test]
    fn a_missing_route_is_never_read_as_a_working_transport() {
        for kind in [
            ProbeKind::Health,
            ProbeKind::WebSocket,
            ProbeKind::Sse,
            ProbeKind::Token,
        ] {
            assert!(!kind.accepts(404));
            assert!(!kind.accepts(501));
            assert!(!kind.accepts(500));
        }
    }

    #[test]
    fn an_answer_that_needs_a_login_still_proves_the_route_was_reached() {
        assert!(ProbeKind::Health.accepts(401));
        assert!(ProbeKind::Health.accepts(403));
        assert!(ProbeKind::Sse.accepts(200));
    }

    #[test]
    fn only_a_served_token_counts_as_a_reachable_transport() {
        assert!(ProbeKind::Token.accepts(200));
        assert!(!ProbeKind::Token.accepts(401));
        assert!(!ProbeKind::Token.accepts(403));
    }

    #[test]
    fn an_upgrade_is_the_answer_a_websocket_route_gives() {
        assert!(ProbeKind::WebSocket.accepts(101));
        assert!(ProbeKind::WebSocket.accepts(426));
    }

    #[test]
    fn only_the_stream_probe_asks_for_a_stream() {
        assert_eq!(ProbeKind::Sse.accept_header(), Some("text/event-stream"));
        assert_eq!(ProbeKind::Health.accept_header(), None);
        assert_eq!(ProbeKind::Token.accept_header(), None);
        assert_eq!(ProbeKind::WebSocket.accept_header(), None);
    }
}
