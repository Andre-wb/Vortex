//! Паттерны SQL-инъекций.

/// Пары «регулярное выражение — описание».
pub const PATTERNS: &[(&str, &str)] = &[
    (
        r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)\b.*\b(FROM|INTO|SET|WHERE|VALUES)\b)",
        "SQL Injection",
    ),
    (r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)", "SQL Boolean Injection"),
    (
        r"(\b(SLEEP|WAITFOR|BENCHMARK)\(.*\))",
        "SQL Time-based Injection",
    ),
    (r"(\b(UNION\s+ALL\s+SELECT)\b)", "Union SQL Injection"),
    (
        r"(\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b)",
        "SQL File Operations",
    ),
    (r"(--\s|#\s|/\*|\*/)", "SQL Comment Injection"),
    (
        r"(\b(XPATH|CONCAT|GROUP_CONCAT)\b.*\()",
        "SQL Function Injection",
    ),
    (
        r"(\b(CASE|WHEN|THEN|END)\b.*\b(WHEN|THEN)\b)",
        "SQL Conditional Injection",
    ),
    (r"(\b(CHAR|ASCII|BIN|HEX)\b.*\()", "SQL Encoding Functions"),
    (r"(\b(IF|ELSE|ENDIF)\b.*\()", "SQL Conditional Functions"),
];
