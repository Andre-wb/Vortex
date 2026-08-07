mod common;

use common::Harness;
use std::sync::Arc;
use vortex_waf::captcha::{ArithmeticChallengeIssuer, HmacChallengeVerifier, HmacSigner};
use vortex_waf::config::GuardConfig;
use vortex_waf::domain::ClientIp;
use vortex_waf::http::{
    BodyPolicy, ExcludedPaths, GuardBuilder, RawHttpRequest, RequestHead, WafGuard,
};
use vortex_waf::ports::ChallengeIssuer;
use vortex_waf::random::SequenceRandom;

fn guard(waf: &Harness, config: GuardConfig) -> WafGuard {
    GuardBuilder::new(Arc::clone(&waf.runtime))
        .with_config(config)
        .with_clock(waf.clock.clone())
        .with_random(Arc::new(
            SequenceRandom::new(vec![0, 2, 3]).with_filler(0x11),
        ))
        .build()
}

#[test]
fn attack_request_gets_a_403_with_violations() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default());
    let raw = RawHttpRequest::get("/api/search")
        .with_peer("203.0.113.60")
        .with_query("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E");

    let outcome = guard.evaluate(&raw);
    assert_eq!(outcome.status(), Some(403));

    let response = outcome.response().unwrap();
    assert_eq!(response.header("x-waf-blocked"), Some("true"));
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["error"], "Request blocked by WAF");
    assert_eq!(body["client_ip"], "203.0.113.60");
    assert!(!body["violations"].as_array().unwrap().is_empty());
    assert!(!body["request_id"].as_str().unwrap().is_empty());
}

#[test]
fn clean_request_passes_through() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default());
    let raw = RawHttpRequest::get("/api/chat/messages")
        .with_peer("203.0.113.61")
        .with_header("user-agent", "Mozilla/5.0");

    assert!(guard.evaluate(&raw).is_pass());
}

#[test]
fn excluded_upload_path_is_not_inspected() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default());
    let raw = RawHttpRequest::post("/api/files/upload-chunk/42", b"' OR 1=1 -- ".to_vec())
        .with_peer("203.0.113.62");

    assert!(guard.evaluate(&raw).is_pass());
}

#[test]
fn oversized_body_is_rejected_with_413() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default().max_body_bytes(128));
    let raw = RawHttpRequest::post("/api/messages", vec![b'a'; 512]).with_peer("203.0.113.63");

    let outcome = guard.evaluate(&raw);
    assert_eq!(outcome.status(), Some(413));
    assert_eq!(
        outcome.response().unwrap().header("connection"),
        Some("close")
    );
}

#[test]
fn lying_content_length_does_not_bypass_the_limit() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default().max_body_bytes(128));
    let mut raw = RawHttpRequest::post("/api/messages", vec![b'a'; 512]).with_peer("203.0.113.64");
    raw.content_length = Some(10);

    assert_eq!(guard.evaluate(&raw).status(), Some(413));
}

#[test]
fn an_excluded_path_is_planned_without_reading_the_body() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default());
    let head = RequestHead::new("POST", "/api/files/upload-chunk/42").with_content_length(1 << 30);

    assert_eq!(guard.plan(&head), BodyPolicy::Skip);
}

#[test]
fn a_request_without_a_body_is_planned_for_analysis_only() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default());

    for method in ["GET", "DELETE", "HEAD", "OPTIONS"] {
        let head = RequestHead::new(method, "/api/chat/messages");
        assert_eq!(
            guard.plan(&head),
            BodyPolicy::InspectHead,
            "метод {method} без тела не должен буферизоваться"
        );
        assert_eq!(
            guard.plan(&head.clone().with_content_length(0)),
            BodyPolicy::InspectHead
        );
    }
}

#[test]
fn a_body_declared_on_any_method_is_inspected() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default().max_body_bytes(128));

    for method in ["GET", "DELETE", "HEAD", "OPTIONS"] {
        let head = RequestHead::new(method, "/api/chat/messages").with_content_length(64);
        assert_eq!(
            guard.plan(&head),
            BodyPolicy::BufferBody { limit: 128 },
            "заявленное тело {method} должно проверяться"
        );
        assert_eq!(
            guard.plan(&head.with_content_length(129)).status(),
            Some(413),
            "предел тела должен действовать и для {method}"
        );
    }
}

#[test]
fn an_oversized_body_is_refused_on_any_method() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default().max_body_bytes(128));

    let mut raw = RawHttpRequest::post("/api/messages", vec![b'a'; 512]).with_peer("203.0.113.68");
    raw.method = "DELETE".to_owned();

    assert_eq!(guard.evaluate(&raw).status(), Some(413));
}

#[test]
fn an_attack_in_a_delete_body_is_blocked() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default());

    let mut raw = RawHttpRequest::post("/api/rooms/7", b"{\"q\": \"' OR 1=1 -- \"}".to_vec())
        .with_peer("203.0.113.69")
        .with_content_type("application/json");
    raw.method = "DELETE".to_owned();

    assert_eq!(guard.evaluate(&raw).status(), Some(403));
}

#[test]
fn a_declared_oversize_is_refused_before_the_body_is_read() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default().max_body_bytes(128));
    let head = RequestHead::new("POST", "/api/messages").with_content_length(129);

    let policy = guard.plan(&head);
    assert_eq!(policy.status(), Some(413));
    assert!(!policy.reads_body());
}

#[test]
fn a_body_carrying_method_is_planned_with_the_configured_limit() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default().max_body_bytes(128));

    for method in ["POST", "PUT", "PATCH"] {
        let head = RequestHead::new(method, "/api/messages").with_content_length(64);
        assert_eq!(guard.plan(&head), BodyPolicy::BufferBody { limit: 128 });
    }

    let without_header = RequestHead::new("POST", "/api/messages");
    assert_eq!(
        guard.plan(&without_header),
        BodyPolicy::BufferBody { limit: 128 }
    );
}

#[test]
fn forged_forwarded_header_does_not_change_the_source() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default());
    let raw = RawHttpRequest::get("/api/search")
        .with_peer("203.0.113.65")
        .with_header("x-forwarded-for", "127.0.0.1")
        .with_query("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E");

    let outcome = guard.evaluate(&raw);
    assert_eq!(outcome.status(), Some(403));
    let body: serde_json::Value =
        serde_json::from_slice(&outcome.response().unwrap().body).unwrap();
    assert_eq!(body["client_ip"], "203.0.113.65");
}

#[test]
fn trusted_proxy_headers_are_honored_when_configured() {
    let waf = Harness::new();
    let guard = guard(&waf, GuardConfig::default().trusted_proxies(["10.0.0.0/8"]));
    let raw = RawHttpRequest::get("/api/search")
        .with_peer("10.0.0.5")
        .with_header("x-forwarded-for", "203.0.113.66")
        .with_query("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E");

    let outcome = guard.evaluate(&raw);
    let body: serde_json::Value =
        serde_json::from_slice(&outcome.response().unwrap().body).unwrap();
    assert_eq!(body["client_ip"], "203.0.113.66");
}

#[test]
fn wrong_captcha_answer_gets_a_429() {
    let waf = Harness::new();
    let signer = Arc::new(HmacSigner::new("тестовый-секрет"));
    let verifier = Arc::new(HmacChallengeVerifier::new(
        signer.clone(),
        waf.clock.clone(),
    ));
    let issuer = ArithmeticChallengeIssuer::new(
        signer,
        waf.clock.clone(),
        Arc::new(SequenceRandom::new(vec![0, 2, 3])),
    );
    let challenge = issuer.issue(&ClientIp::from("203.0.113.67"));

    let guard = GuardBuilder::new(Arc::clone(&waf.runtime))
        .with_clock(waf.clock.clone())
        .with_random(Arc::new(SequenceRandom::new(vec![0])))
        .with_captcha_verifier(verifier)
        .build();

    let base = RawHttpRequest::get("/api/chat/messages")
        .with_peer("203.0.113.67")
        .with_header("user-agent", "Mozilla/5.0")
        .with_header("x-captcha-id", &challenge.challenge_id);

    let wrong = base.clone().with_header("x-captcha-answer", "99");
    let outcome = guard.evaluate(&wrong);
    assert_eq!(outcome.status(), Some(429));
    assert_eq!(
        outcome.response().unwrap().header("x-waf-captcha-required"),
        Some("true")
    );

    let correct = base.with_header("x-captcha-answer", "7");
    assert!(guard.evaluate(&correct).is_pass());
}

#[test]
fn custom_excluded_paths_replace_the_defaults() {
    let waf = Harness::new();
    let guard = GuardBuilder::new(Arc::clone(&waf.runtime))
        .with_clock(waf.clock.clone())
        .with_random(Arc::new(SequenceRandom::new(vec![0])))
        .with_excluded_paths(ExcludedPaths::new(["/internal/"]))
        .build();

    assert!(guard.excluded_paths().contains("/internal/metrics"));
    assert!(!guard.excluded_paths().contains("/health"));
}
