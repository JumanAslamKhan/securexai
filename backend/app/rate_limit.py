import math
import os
import threading
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class RateLimitMiddleware:
    def __init__(self, app: Callable[..., Awaitable[Response]]) -> None:
        self.app = app
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http" or not scope["path"].startswith("/api/v1/"):
            await self.app(scope, receive, send)
            return

        limit = max(1, int(os.getenv("SECUREXAI_RATE_LIMIT", "60")))
        window = max(1, int(os.getenv("SECUREXAI_RATE_WINDOW_SECONDS", "60")))
        client = scope.get("client")
        client_key = client[0] if client else "unknown"
        now = time.monotonic()
        reset_at = now + window

        with self._lock:
            timestamps = [timestamp for timestamp in self._requests[client_key] if timestamp > now - window]
            self._requests[client_key] = timestamps
            if timestamps:
                reset_at = timestamps[0] + window
            remaining = max(0, limit - len(timestamps) - 1)
            if len(timestamps) >= limit:
                retry_after = max(1, math.ceil(reset_at - now))
                response = JSONResponse(
                    {"detail": "Rate limit exceeded. Try again later."},
                    status_code=429,
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(math.ceil(reset_at)),
                    },
                )
                await response(scope, receive, send)
                return
            timestamps.append(now)

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-ratelimit-limit", str(limit).encode()),
                        (b"x-ratelimit-remaining", str(remaining).encode()),
                        (b"x-ratelimit-reset", str(math.ceil(reset_at)).encode()),
                    ]
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
