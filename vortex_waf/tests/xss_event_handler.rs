mod common;

use common::{has_rule, Harness};
use vortex_waf::domain::{Analysis, RequestBuilder};

const EVENT_HANDLER: &str = "XSS-013";

const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn analyze_json_field(waf: &Harness, value: &str) -> Analysis {
    let body = serde_json::json!({ "data_b64": value }).to_string();
    waf.runtime.analyze(
        &RequestBuilder::new()
            .client_ip("203.0.113.80")
            .method("POST")
            .path("/api/privacy/unpad")
            .content_type("application/json")
            .body(body)
            .build(),
    )
}

fn base64_corpus(count: usize) -> Vec<String> {
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut corpus = Vec::with_capacity(count);
    for _ in 0..count {
        let mut text = String::with_capacity(44);
        for _ in 0..43 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let index = (state >> 33) as usize % BASE64_ALPHABET.len();
            text.push(BASE64_ALPHABET[index] as char);
        }
        text.push('=');
        corpus.push(text);
    }
    corpus
}

#[test]
fn base64_payloads_do_not_look_like_event_handlers() {
    let waf = Harness::new();
    let mut blocked = Vec::new();
    for value in base64_corpus(400) {
        let analysis = analyze_json_field(&waf, &value);
        if analysis.block || has_rule(&analysis, EVENT_HANDLER) {
            blocked.push((value, analysis.findings.clone()));
        }
    }
    assert!(
        blocked.is_empty(),
        "случайные base64-строки приняты за атаку: {blocked:?}"
    );
}

#[test]
fn the_documented_false_positive_is_gone() {
    let waf = Harness::new();
    for value in [
        "cGFkZGVkIGRhdGEgd2l0aCBub2lzZQon4jK=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dndon9zK=",
    ] {
        let analysis = analyze_json_field(&waf, value);
        assert!(!has_rule(&analysis, EVENT_HANDLER), "сработало на {value}");
        assert!(!analysis.block, "заблокировано: {value}");
    }
}

#[test]
fn real_event_handler_injections_are_still_caught() {
    let waf = Harness::new();
    for payload in [
        "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<img/onerror=alert(1)>",
        "\" onmouseover=\"alert(1)",
        "'onfocus='alert(1)",
        "<body onload = alert(1)>",
        "<details ontoggle=alert(1)>",
        "onerror=alert(1)",
    ] {
        let analysis = analyze_json_field(&waf, payload);
        assert!(
            has_rule(&analysis, EVENT_HANDLER),
            "не поймано правилом {EVENT_HANDLER}: {payload}"
        );
        assert!(analysis.block, "не заблокировано: {payload}");
    }
}

#[test]
fn an_event_handler_in_a_query_parameter_is_caught() {
    let waf = Harness::new();
    let analysis = waf.runtime.analyze(
        &RequestBuilder::new()
            .client_ip("203.0.113.81")
            .path("/api/search")
            .query("q=%3Csvg+onload%3Dalert(1)%3E")
            .build(),
    );
    assert!(has_rule(&analysis, EVENT_HANDLER));
    assert!(analysis.block);
}
