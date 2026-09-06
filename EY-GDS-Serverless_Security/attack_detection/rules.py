"""
Detection rules for suspicious serverless/API requests.

These rules are intended for defensive security monitoring.
"""

# Patterns commonly associated with SQL injection.
SQL_INJECTION_PATTERNS = [
    "' or ",
    '" or "',
    "' and ",
    '" and "',
    "union select",
    "union all select",
    "'--",
    '"--',
    "or 1=1",
    "and 1=1",
]

# Patterns commonly associated with command injection.
COMMAND_INJECTION_PATTERNS = [
    "&&",
    "||",
    "$(",
    "`",
    ";whoami",
    ";id",
    ";uname",
]

# Directory traversal patterns.
PATH_TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
]

# Suspicious HTTP methods for a typical API.
SUSPICIOUS_HTTP_METHODS = {
    "TRACE",
    "CONNECT",
}