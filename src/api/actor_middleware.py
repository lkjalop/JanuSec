from typing import Callable, Awaitable
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.requests import Request
from src.api.actor_context import set_current_actor


class ActorHeaderMiddleware:
    """ASGI middleware that reads `x-actor` header and sets it into the actor context var
    for the lifetime of the request.
    """
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get('type') != 'http':
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        actor = request.headers.get('x-actor') or request.headers.get('X-Actor')
        # Use context manager to set actor for request lifetime
        with set_current_actor(actor):
            await self.app(scope, receive, send)
