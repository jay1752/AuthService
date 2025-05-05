from fastapi import APIRouter
from app.core.config import settings

api_router = APIRouter()

from app.api.v1 import buildings

api_router = APIRouter()

api_router.include_router(buildings.router, prefix="/test", tags=["buildings"]) 
