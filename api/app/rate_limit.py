"""Rate limiting with sliding window algorithm."""

import time
from collections import defaultdict, deque
from typing import DefaultDict, Deque

from fastapi import HTTPException, Request, status

from .config import settings
from .logging_config import logger


class SlidingWindowRateLimiter:
    """
    Simple in-memory sliding window rate limiter.

    Tracks requests per client IP and enforces rate limits.
    In production, this should be replaced with Redis or similar.
    """

    def __init__(
        self, max_requests: int, window_seconds: int
    ) -> None:
        """
        Initialize rate limiter.

        Args:
            max_requests: Maximum number of requests allowed in window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Store timestamps of requests per client
        self.requests: DefaultDict[str, Deque[float]] = defaultdict(deque)

    def _clean_old_requests(self, client_id: str, current_time: float) -> None:
        """Remove requests older than the time window."""
        cutoff_time = current_time - self.window_seconds

        while self.requests[client_id] and self.requests[client_id][0] < cutoff_time:
            self.requests[client_id].popleft()

    def is_allowed(self, client_id: str) -> tuple[bool, int]:
        """
        Check if request is allowed for client.

        Args:
            client_id: Client identifier (usually IP address)

        Returns:
            Tuple of (is_allowed, remaining_requests)
        """
        current_time = time.time()

        # Clean old requests
        self._clean_old_requests(client_id, current_time)

        # Check if limit exceeded
        request_count = len(self.requests[client_id])

        if request_count >= self.max_requests:
            logger.warning(
                "Rate limit exceeded",
                extra={"client_id": client_id, "request_count": request_count},
            )
            return False, 0

        # Add current request
        self.requests[client_id].append(current_time)

        remaining = self.max_requests - request_count - 1
        logger.debug(
            "Rate limit check passed",
            extra={"client_id": client_id, "remaining": remaining},
        )

        return True, remaining

    def get_retry_after(self, client_id: str) -> int:
        """
        Get seconds until the client can make another request.

        Args:
            client_id: Client identifier

        Returns:
            Seconds to wait before retry
        """
        if not self.requests[client_id]:
            return 0

        oldest_request = self.requests[client_id][0]
        retry_after = int(oldest_request + self.window_seconds - time.time())
        return max(0, retry_after)


# Global rate limiter instance
rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds,
)


async def check_rate_limit(request: Request) -> None:
    """
    Dependency to check rate limit for incoming requests.

    Args:
        request: FastAPI request object

    Raises:
        HTTPException: 429 if rate limit exceeded
    """
    # Use client IP as identifier
    client_ip = request.client.host if request.client else "unknown"

    allowed, remaining = rate_limiter.is_allowed(client_ip)

    if not allowed:
        retry_after = rate_limiter.get_retry_after(client_ip)

        logger.warning(
            "Rate limit exceeded for client",
            extra={"client_ip": client_ip, "retry_after": retry_after},
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    # Add rate limit info to response headers (will be added by middleware)
    request.state.rate_limit_remaining = remaining
