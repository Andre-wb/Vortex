//! Паттерны инъекций команд ОС.

pub const PATTERNS: &[(&str, &str)] = &[
    (
        r"(;\s*(ls|dir|cat|more|less|head|tail|ps|netstat|ifconfig|ipconfig))",
        "Command Injection",
    ),
    (
        r"(\|\s*(ls|dir|cat|more|less|head|tail))",
        "Pipe Command Injection",
    ),
    (
        r"(&&\s*(ls|dir|cat|more|less|head|tail))",
        "AND Command Injection",
    ),
    (
        r"(\|\|\s*(ls|dir|cat|more|less|head|tail))",
        "OR Command Injection",
    ),
    (r"(\$(\(.*\)|\{.*\}))", "Bash Command Substitution"),
    (r"(`.*`)", "Backtick Command Execution"),
    (
        r"(wget\s+|curl\s+|nc\s+|ncat\s+|telnet\s+)",
        "Network Tools",
    ),
    (r"(python\s+|perl\s+|ruby\s+|php\s+)", "Script Execution"),
    (r"(base64\s+-d|base64\s+-decode)", "Base64 Decode Command"),
    (r"(sh\s+-i|bash\s+-i|zsh\s+-i)", "Reverse Shell"),
];
