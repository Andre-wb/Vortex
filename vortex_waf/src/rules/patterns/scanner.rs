//! Паттерны сканеров уязвимостей и переборщиков каталогов.

pub const PATTERNS: &[(&str, &str)] = &[
    (
        r"(nmap|nikto|sqlmap|metasploit|nessus|acunetix|w3af|skipfish|burpsuite|zap)",
        "Security Scanner",
    ),
    (
        r"(dirb|gobuster|ffuf|wfuzz|dirbuster)",
        "Directory Brute Force",
    ),
    (r"(wp-admin|wp-login|wp-content)", "WordPress Scanner"),
    (
        r"(phpmyadmin|adminer|mysql-admin)",
        "Database Admin Scanner",
    ),
    (
        r"(\.git/HEAD|\.svn/entries|\.hg/store)",
        "Version Control Scanner",
    ),
    (
        r"(robots\.txt|sitemap\.xml|crossdomain\.xml)",
        "Crawler Directives",
    ),
    (r"(\.DS_Store|Thumbs\.db|desktop\.ini)", "OS Metadata Files"),
];
