//! Разбор multipart-тела в составе полного анализа.

mod common;

use common::{has_rule, has_rule_prefix, multipart_body, Harness, MULTIPART_CONTENT_TYPE};
use vortex_waf::domain::RequestBuilder;

fn multipart_request(body: String) -> vortex_waf::domain::InspectedRequest {
    RequestBuilder::new()
        .client_ip("203.0.113.20")
        .method("POST")
        .path("/api/files/attach")
        .content_type(MULTIPART_CONTENT_TYPE)
        .body(body)
        .build()
}

#[test]
fn webshell_upload_is_blocked() {
    let waf = Harness::new();
    let body = multipart_body(&[(
        r#"Content-Disposition: form-data; name="file"; filename="backdoor.php""#,
        "<?php system($_GET['c']); ?>",
    )]);

    let analysis = waf.runtime.analyze(&multipart_request(body));
    assert!(analysis.block);
    assert!(has_rule(&analysis, "DANGEROUS-UPLOAD"));
}

#[test]
fn webshell_name_in_the_file_name_text_field_is_blocked() {
    let waf = Harness::new();
    // Точка возобновляемой загрузки передаёт имя обычным текстовым полем.
    let body = multipart_body(&[
        (
            r#"Content-Disposition: form-data; name="file_name""#,
            "backdoor.php",
        ),
        (
            r#"Content-Disposition: form-data; name="total_size""#,
            "1024",
        ),
    ]);

    let analysis = waf.runtime.analyze(&multipart_request(body));
    assert!(analysis.block);
    assert!(has_rule(&analysis, "DANGEROUS-UPLOAD"));
}

#[test]
fn source_code_upload_is_allowed() {
    let waf = Harness::new();
    let body = multipart_body(&[(
        r#"Content-Disposition: form-data; name="file"; filename="script.py""#,
        "print(1)",
    )]);

    let analysis = waf.runtime.analyze(&multipart_request(body));
    assert!(!analysis.block, "находки: {:?}", analysis.findings);
}

#[test]
fn injection_inside_a_text_field_is_caught() {
    let waf = Harness::new();
    // Полезная нагрузка спрятана в значении текстового поля.
    let body = multipart_body(&[(
        r#"Content-Disposition: form-data; name="comment""#,
        "1' UNION ALL SELECT password FROM users --",
    )]);

    let analysis = waf.runtime.analyze(&multipart_request(body));
    assert!(analysis.block);
    assert!(has_rule_prefix(&analysis, "SQLI"));
}

#[test]
fn binary_file_content_does_not_produce_false_positives() {
    let waf = Harness::new();
    // Содержимое файла похоже на инъекцию, но это байты вложения.
    let body = multipart_body(&[(
        r#"Content-Disposition: form-data; name="file"; filename="photo.png""#,
        "\u{0}\u{1}SELECT * FROM users; DROP TABLE users",
    )]);

    let analysis = waf.runtime.analyze(&multipart_request(body));
    assert!(!analysis.block, "находки: {:?}", analysis.findings);
}

#[test]
fn traversal_in_a_filename_is_blocked() {
    let waf = Harness::new();
    let body = multipart_body(&[(
        r#"Content-Disposition: form-data; name="file"; filename="../../etc/passwd""#,
        "данные",
    )]);

    let analysis = waf.runtime.analyze(&multipart_request(body));
    assert!(analysis.block);
    assert!(has_rule(&analysis, "PATH-TRAVERSAL"));
}

#[test]
fn double_dots_in_ordinary_text_are_not_traversal() {
    let waf = Harness::new();
    let body = multipart_body(&[(
        r#"Content-Disposition: form-data; name="comment""#,
        "смотри файл report..txt, ну и что дальше...",
    )]);

    let analysis = waf.runtime.analyze(&multipart_request(body));
    assert!(!analysis.block, "находки: {:?}", analysis.findings);
}
