"""WAF Rule и WAFSignature — паттерны атак."""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import List, Optional

logger = logging.getLogger(__name__)


class WAFRule:
    # Truncate input to this length before matching to prevent ReDoS from crafted payloads
    _MAX_INPUT = 4096

    def __init__(self, rule_id: str, pattern: str, severity: str = "medium",
                 description: str = "", action: str = "block"):
        self.rule_id = rule_id
        try:
            self.pattern = re.compile(pattern, re.IGNORECASE)
        except re.error:
            self.pattern = re.compile(r"(?!)", re.IGNORECASE)
            logger.error(f"Failed to compile rule {rule_id}: {pattern}")
        self.severity = severity
        self.description = description
        self.action = action
        self.trigger_count = 0
        self.last_triggered: Optional[datetime] = None

    def match(self, text: str) -> bool:
        """Regex match with input length cap to prevent catastrophic backtracking (ReDoS)."""
        return bool(self.pattern.search(text[:self._MAX_INPUT]))


class WAFSignature:
    SQL_INJECTION_PATTERNS = [
        (r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)\b.*\b(FROM|INTO|SET|WHERE|VALUES)\b)", "SQL Injection"),
        (r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)", "SQL Boolean Injection"),
        (r"(\b(SLEEP|WAITFOR|BENCHMARK)\(.*\))", "SQL Time-based Injection"),
        (r"(\b(UNION\s+ALL\s+SELECT)\b)", "Union SQL Injection"),
        (r"(\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b)", "SQL File Operations"),
        (r"(--\s|#\s|/\*|\*/)", "SQL Comment Injection"),
        (r"(\b(XPATH|CONCAT|GROUP_CONCAT)\b.*\()", "SQL Function Injection"),
        (r"(\b(CASE|WHEN|THEN|END)\b.*\b(WHEN|THEN)\b)", "SQL Conditional Injection"),
        (r"(\b(CHAR|ASCII|BIN|HEX)\b.*\()", "SQL Encoding Functions"),
        (r"(\b(IF|ELSE|ENDIF)\b.*\()", "SQL Conditional Functions"),
    ]

    XSS_PATTERNS = [
        (r"(<script.*?>.*?</script>)", "Script Tag XSS"),
        (r"(javascript:)", "JavaScript Protocol XSS"),
        (r"(on\w+\s*=)", "Event Handler XSS"),
        (r"(alert\(.*\))", "Alert XSS"),
        (r"(document\.(cookie|location|domain|referrer))", "Document Object XSS"),
        (r"(window\.(location|open))", "Window Object XSS"),
        (r"(eval\(.*\))", "Eval XSS"),
        (r"(setTimeout|setInterval).*\(.*\)", "Timer XSS"),
        (r"(<iframe.*?>.*?</iframe>)", "IFrame XSS"),
        (r"(<img.*?src.*?=.*?javascript:)", "IMG Tag XSS"),
        (r"(<svg.*?onload.*?=)", "SVG XSS"),
        (r"(<body.*?onload.*?=)", "Body Tag XSS"),
        (r"(<input.*?onfocus.*?=)", "Input Tag XSS"),
        (r"(<marquee.*?onstart.*?=)", "Marquee Tag XSS"),
        (r"(<details.*?ontoggle.*?=)", "Details Tag XSS"),
        (r"(<select.*?onchange.*?=)", "Select Tag XSS"),
    ]

    PATH_TRAVERSAL_PATTERNS = [
        (r"(\.\./|\.\.\\)", "Directory Traversal"),
        (r"(/etc/passwd|/etc/shadow|/etc/hosts)", "System File Access"),
        (r"(c:\\windows\\system32\\config\\sam)", "Windows SAM File"),
        (r"(\.\.%2f|\.\.%5c)", "Encoded Directory Traversal"),
        (r"(%00|%0a|%0d)", "Null Byte Injection"),
        (r"(/proc/self/environ|/proc/self/cmdline)", "Proc Filesystem Access"),
        (r"(\.git/|\.svn/|\.hg/)", "Version Control Files"),
        (r"(\.env|\.htaccess|\.htpasswd)", "Configuration Files"),
        (r"(php://filter|zip://|phar://)", "PHP Wrappers"),
        (r"(file://|ftp://|gopher://)", "Dangerous Protocols"),
    ]

    COMMAND_INJECTION_PATTERNS = [
        (r"(;\s*(ls|dir|cat|more|less|head|tail|ps|netstat|ifconfig|ipconfig))", "Command Injection"),
        (r"(\|\s*(ls|dir|cat|more|less|head|tail))", "Pipe Command Injection"),
        (r"(&&\s*(ls|dir|cat|more|less|head|tail))", "AND Command Injection"),
        (r"(\|\|\s*(ls|dir|cat|more|less|head|tail))", "OR Command Injection"),
        (r"(\$(\(.*\)|\{.*\}))", "Bash Command Substitution"),
        (r"(`.*`)", "Backtick Command Execution"),
        (r"(wget\s+|curl\s+|nc\s+|ncat\s+|telnet\s+)", "Network Tools"),
        (r"(python\s+|perl\s+|ruby\s+|php\s+)", "Script Execution"),
        (r"(base64\s+-d|base64\s+-decode)", "Base64 Decode Command"),
        (r"(sh\s+-i|bash\s+-i|zsh\s+-i)", "Reverse Shell"),
    ]

    FILE_INCLUSION_PATTERNS = [
        (r"(include\(.*\)|require\(.*\)|include_once\(.*\)|require_once\(.*\))", "File Inclusion"),
        (r"(\.\./\.\./\.\./)", "Multiple Directory Traversal"),
        (r"(http://|https://|ftp://).*(\.php|\.asp|\.aspx|\.jsp)", "Remote File Inclusion"),
        (r"(php://input|data://)", "PHP Stream Wrappers"),
        (r"(expect://|ssh2://)", "Dangerous PHP Wrappers"),
        (r"(\./\./\./)", "Relative Path Traversal"),
    ]

    SSRF_PATTERNS = [
        (r"(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)", "Localhost Access"),
        (r"(169\.254\.169\.254|metadata\.google\.internal)", "Cloud Metadata"),
        (r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+)", "Private IP Range"),
        (r"(file://|gopher://|dict://)", "Dangerous URL Schemes"),
        (r"(admin|internal|backend|management)", "Internal Service Names"),
    ]

    XXE_PATTERNS = [
        (r"(<!DOCTYPE.*\[.*\])", "XML DOCTYPE Declaration"),
        (r"(<!ENTITY.*SYSTEM.*>)", "XML External Entity"),
        (r"(file:///|http://|ftp://).*ENTITY", "External Entity Reference"),
        (r"\b(XXE|XML External Entity)\b", "XXE Keyword"),
        (r"(<!ELEMENT|<!ATTLIST)", "XML Schema Elements"),
    ]

    API_ABUSE_PATTERNS = [
        (r"(/api/.*(admin|delete|drop|truncate))", "Admin API Abuse"),
        (r"(/v[0-9]+/.*)", "API Version Enumeration"),
        (r"(swagger|openapi|api-docs)", "API Documentation"),
        (r"(\.json|\.xml|\.yaml|\.yml)", "API Data Formats"),
        (r"(limit=1000|limit=9999)", "Large Result Set"),
        (r"(offset=10000|page=1000)", "Deep Pagination"),
    ]

    SCANNER_PATTERNS = [
        (r"(nmap|nikto|sqlmap|metasploit|nessus|acunetix|w3af|skipfish|burpsuite|zap)", "Security Scanner"),
        (r"(dirb|gobuster|ffuf|wfuzz|dirbuster)", "Directory Brute Force"),
        (r"(wp-admin|wp-login|wp-content)", "WordPress Scanner"),
        (r"(phpmyadmin|adminer|mysql-admin)", "Database Admin Scanner"),
        (r"(\.git/HEAD|\.svn/entries|\.hg/store)", "Version Control Scanner"),
        (r"(robots\.txt|sitemap\.xml|crossdomain\.xml)", "Crawler Directives"),
        (r"(\.DS_Store|Thumbs\.db|desktop\.ini)", "OS Metadata Files"),
    ]

    @classmethod
    def get_all_rules(cls) -> List[WAFRule]:
        rules = []
        counter = 1
        for patterns, prefix, severity, action in [
            (cls.SQL_INJECTION_PATTERNS, "SQLI", "critical", "block"),
            (cls.XSS_PATTERNS, "XSS", "high", "block"),
            (cls.PATH_TRAVERSAL_PATTERNS, "PT", "high", "block"),
            (cls.COMMAND_INJECTION_PATTERNS, "CI", "critical", "block"),
            (cls.FILE_INCLUSION_PATTERNS, "FI", "high", "block"),
            (cls.SSRF_PATTERNS, "SSRF", "medium", "alert"),
            (cls.XXE_PATTERNS, "XXE", "high", "block"),
            (cls.API_ABUSE_PATTERNS, "API", "medium", "alert"),
            (cls.SCANNER_PATTERNS, "SCAN", "low", "log"),
        ]:
            for pattern, desc in patterns:
                rules.append(WAFRule(
                    rule_id=f"{prefix}-{counter:03d}",
                    pattern=pattern, severity=severity,
                    description=desc, action=action,
                ))
                counter += 1
        return rules
