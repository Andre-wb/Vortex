//! Паттерны локального и удалённого подключения файлов.

pub const PATTERNS: &[(&str, &str)] = &[
    (
        r"(include\(.*\)|require\(.*\)|include_once\(.*\)|require_once\(.*\))",
        "File Inclusion",
    ),
    (r"(\.\./\.\./\.\./)", "Multiple Directory Traversal"),
    (
        r"(http://|https://|ftp://).*(\.php|\.asp|\.aspx|\.jsp)",
        "Remote File Inclusion",
    ),
    (r"(php://input|data://)", "PHP Stream Wrappers"),
    (r"(expect://|ssh2://)", "Dangerous PHP Wrappers"),
    (r"(\./\./\./)", "Relative Path Traversal"),
];
