"""Host comparisons for evidence classification; never substring trust checks."""
from urllib.parse import urlsplit


def domain_host(value: str) -> str:
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        return ""
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        if parsed.username is not None or parsed.password is not None:
            return ""
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def host_matches(value: str, domain: str, *, subdomains: bool = True) -> bool:
    host = domain_host(value)
    return host == domain or bool(subdomains and host.endswith("." + domain))
