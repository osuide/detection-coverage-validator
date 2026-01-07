"""SQL utility functions for safe query construction.

Security Considerations:
- escape_like_pattern() prevents LIKE injection attacks (CWE-89)
- Always use parameterised queries in addition to escaping
"""


def escape_like_pattern(pattern: str) -> str:
    """Escape special characters in LIKE patterns.

    LIKE patterns use % and _ as wildcards. User input containing these
    characters could cause:
    - Denial of service via expensive regex patterns
    - Information disclosure through wildcard abuse

    Args:
        pattern: User-provided search string

    Returns:
        Escaped string safe for use in LIKE patterns

    Example:
        >>> escape_like_pattern("test%value")
        "test\\%value"
        >>> escape_like_pattern("user_name")
        "user\\_name"
    """
    # Escape backslash first (since we use it as escape char)
    pattern = pattern.replace("\\", "\\\\")
    # Escape LIKE wildcards
    pattern = pattern.replace("%", "\\%")
    pattern = pattern.replace("_", "\\_")
    return pattern
