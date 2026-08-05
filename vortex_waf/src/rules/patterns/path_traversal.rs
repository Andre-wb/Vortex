//! Паттерны обхода каталогов и доступа к системным файлам.

pub const PATTERNS: &[(&str, &str)] = &[
    (r"(\.\./|\.\.\\)", "Directory Traversal"),
    (
        r"(/etc/passwd|/etc/shadow|/etc/hosts)",
        "System File Access",
    ),
    (r"(c:\\windows\\system32\\config\\sam)", "Windows SAM File"),
    (r"(\.\.%2f|\.\.%5c)", "Encoded Directory Traversal"),
    (r"(%00|%0a|%0d)", "Null Byte Injection"),
    (
        r"(/proc/self/environ|/proc/self/cmdline)",
        "Proc Filesystem Access",
    ),
    (r"(\.git/|\.svn/|\.hg/)", "Version Control Files"),
    (r"(\.env|\.htaccess|\.htpasswd)", "Configuration Files"),
    (r"(php://filter|zip://|phar://)", "PHP Wrappers"),
];
