import logging
import re
import time
import uuid
from html import escape

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.base import BaseHTTPMiddleware

from app import models  # noqa: F401
from app.api.router import api_router
from app.core.config import settings
from app.db.session import engine
from app.models.base import Base

MAX_DEMO_CREDENTIAL_LENGTH = 120
MAX_DEMO_QUERY_LENGTH = 200


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"

        logging.getLogger("app.request").info(
            "request_complete",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": elapsed_ms,
                "request_id": request_id,
            },
        )
        return response


def configure_logging() -> None:
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def create_application() -> FastAPI:
    configure_logging()
    app = FastAPI(
        title=settings.app_name,
        version="0.3.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    def startup() -> None:
        try:
            Base.metadata.create_all(bind=engine)
        except SQLAlchemyError:
            logging.getLogger(__name__).warning("Database unavailable on startup; continuing without auto-create")

    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/health", tags=["health"])
    def health_check() -> dict[str, str]:
        return {"status": "ok"}

    class DemoLoginRequest(BaseModel):
        username: str = Field(min_length=1, max_length=MAX_DEMO_CREDENTIAL_LENGTH)
        password: str = Field(min_length=1, max_length=MAX_DEMO_CREDENTIAL_LENGTH)

    class DemoSearchRequest(BaseModel):
        query: str = Field(min_length=1, max_length=MAX_DEMO_QUERY_LENGTH)

    @app.post("/login", tags=["demo"])
    def demo_login(payload: DemoLoginRequest) -> dict[str, object]:
        """
        Demo/testing only: simulated SQLi detection endpoint.
        This does not execute dynamic SQL and is intentionally isolated from production auth flows.
        """
        suspicious = bool(re.search(r"(?i)(\bor\b\s+\d+=\d+|union\s+select|--|;\s*drop\s+table)", payload.username))
        return {
            "demo_only": True,
            "warning": "Testing endpoint only. Do not use in production.",
            "simulated_vulnerability": "SQL injection pattern detected" if suspicious else None,
            "login_result": "blocked" if suspicious else "accepted",
            "safe_evidence": escape(payload.username)[:80],
            "security_note": "Use parameterized queries and strict input validation.",
        }

    @app.post("/search", tags=["demo"])
    def demo_search(payload: DemoSearchRequest) -> dict[str, object]:
        """
        Demo/testing only: simulated reflected-XSS behavior using safely escaped output.
        """
        suspicious = bool(re.search(r"(?i)(<script\b|onerror\s*=|onload\s*=|javascript:)", payload.query))
        safe_render = escape(payload.query)
        return {
            "demo_only": True,
            "warning": "Testing endpoint only. Do not use in production.",
            "simulated_vulnerability": "XSS payload pattern detected" if suspicious else None,
            "safe_rendered_result": f"Search results for: {safe_render}",
            "security_note": "Always output-encode untrusted data and use a strict CSP.",
        }

    @app.get("/ready", tags=["health"])
    def readiness_check() -> dict[str, str]:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return {"status": "ready"}
        except Exception:
            return {"status": "degraded"}

    return app


app = create_application()
