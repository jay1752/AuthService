from typing import Any, Dict, List
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from app.services.db.mysql_client import mysql_client
from app.service.cognito.cognito_verify import get_current_user
router = APIRouter()


class Building(BaseModel):
    id: int
    name: str
    address: str
    city: str
    state: str
    country: str
    zip_code: str
    latitude: float | None = None
    longitude: float | None = None
    total_floors: int
    year_built: int | None = None
    total_area_sqft: float | None = None
    building_type: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


@router.get("/all_buildings", response_model=List[Building], )
async def get_all_buildings(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Get all buildings from the database.
    """
    try:
        await mysql_client.initialize()
        buildings = await mysql_client.select("SELECT * FROM buildings")
        await mysql_client.close()
        return buildings
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}") 