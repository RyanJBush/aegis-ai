from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request, status

from app.core.config import settings


class RateLimitService:
    _hits: dict[str, deque[datetime]] = defaultdict(deque)

    @classmethod
    def check_auth_rate_limit(cls, request: Request) -> None:
        client = request.client.host if request.client else "unknown"
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=1)
        bucket = cls._hits[client]

        while bucket and bucket[0] < window_start:
            bucket.popleft()

        if len(bucket) >= settings.auth_rate_limit_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for auth endpoints",
            )

        bucket.append(now)
