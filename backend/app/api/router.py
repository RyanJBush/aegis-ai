from fastapi import APIRouter

from app.api.routers import ai, app_data, auth, observability, scanning, vulnerabilities

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(app_data.router, prefix="/app", tags=["app-data"])
api_router.include_router(scanning.router, prefix="/scanning", tags=["scanning"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])

api_router.include_router(ai.router, prefix="/ai", tags=["ai-assistant"])

api_router.include_router(observability.router, prefix="/observability", tags=["observability"])
