"""HTTP exception classes used by integrations to surface retry-after info."""

from typing import Optional, Dict, Any


class HTTPRetryError(Exception):
    """HTTP error that carries parsed retry_after seconds and optional response.

    Attributes:
        retry_after: number of seconds client should wait before retrying (may be None)
        status_code: numeric HTTP status code when available
        response: raw response object when available
    """

    def __init__(self, message: str, retry_after: Optional[float] = None, status_code: Optional[int] = None, response: Optional[Any] = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.status_code = status_code
        self.response = response


class RefreshTokenRevoked(Exception):
    """Raised when a refresh token is known to be revoked and cannot be used."""

    pass
