from fastapi import APIRouter

from app.api.v1 import auth, buildings

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(buildings.router, prefix="/test", tags=["buildings"]) 