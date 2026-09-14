"""HTTP-only connector transport with explicit redirect and proxy policy."""
import urllib.request
from urllib.parse import urlsplit
from src.security.egress_guard import ssrf_check


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def safe_urlopen(request, *, timeout=20, allow_private=False):
    url = request.full_url if isinstance(request, urllib.request.Request) else request
    parsed = urlsplit(url)
    if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Invalid connector URL')
    if not allow_private:
        if parsed.scheme != 'https':
            raise ValueError('Public connector requires HTTPS')
        ok, _ = ssrf_check(url)
        if not ok:
            raise ValueError('Connector URL violates outbound policy')
    # allow_private is reserved for operator-configured dependency health probes.
    # Redirects must never forward provider credentials to another destination.
    return _OPENER.open(request, timeout=timeout)
