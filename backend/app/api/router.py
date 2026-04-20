from fastapi import APIRouter

from app.api.routers import app_data, auth, scanning, vulnerabilities

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(app_data.router, prefix="/app", tags=["app-data"])
api_router.include_router(scanning.router, prefix="/scanning", tags=["scanning"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
