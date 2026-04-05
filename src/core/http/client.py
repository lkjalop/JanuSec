import httpx
from typing import Callable, Optional

def _retryable(status: int) -> bool:
    return status in (429, 500, 502, 503, 504)

async def request_with_retry(
    method: str,
    url: str,
    *,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    json: Optional[dict] = None,
    timeout: float = 15.0,
    retries: int = 3,
    backoff_base: float = 0.5,
    circuit_breaker: Optional[Callable[[httpx.Response], bool]] = None,
) -> httpx.Response:
    async with httpx.AsyncClient(timeout=timeout) as client:
        attempt = 0
        while True:
            resp = await client.request(method, url, headers=headers, params=params, data=data, json=json)
            if circuit_breaker and circuit_breaker(resp):
                return resp
            if resp.status_code < 400:
                return resp
            if attempt >= retries or not _retryable(resp.status_code):
                return resp
            attempt += 1
            # exponential backoff with jitter
            import asyncio, random
            wait = backoff_base * (2 ** (attempt - 1)) + random.uniform(0, 0.25)
            await asyncio.sleep(wait)


def request_with_retry_sync(
    method: str,
    url: str,
    *,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    json: Optional[dict] = None,
    timeout: float = 15.0,
    retries: int = 3,
    backoff_base: float = 0.5,
    circuit_breaker: Optional[Callable[[httpx.Response], bool]] = None,
) -> httpx.Response:
    import time, random
    with httpx.Client(timeout=timeout) as client:
        attempt = 0
        while True:
            resp = client.request(method, url, headers=headers, params=params, data=data, json=json)
            if circuit_breaker and circuit_breaker(resp):
                return resp
            if resp.status_code < 400:
                return resp
            if attempt >= retries or not _retryable(resp.status_code):
                return resp
            attempt += 1
            wait = backoff_base * (2 ** (attempt - 1)) + random.uniform(0, 0.25)
            time.sleep(wait)
