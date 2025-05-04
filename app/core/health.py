from fastapi import APIRouter, status
from pydantic import BaseModel
from app.core.config import settings


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str


health_router = APIRouter()


@health_router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health check endpoint",
    description="Returns the health status of the service."
)
async def health_check():
    """
    Health check endpoint which returns status, version and environment.
    Used by Kubernetes probes and monitoring systems.
    """
    return HealthResponse(
        status="healthy",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT
    )


@health_router.get(
    "/readiness",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Readiness probe endpoint",
    description="Returns the readiness status of the service."
)
async def readiness():
    """
    Readiness probe endpoint which returns status, version and environment.
    Used by Kubernetes readiness probes.
    """
    return HealthResponse(
        status="ready",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT
    )


@health_router.get(
    "/liveness",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Liveness probe endpoint",
    description="Returns the liveness status of the service."
)
async def liveness():
    """
    Liveness probe endpoint which returns status, version and environment.
    Used by Kubernetes liveness probes.
    """
    return HealthResponse(
        status="alive",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT
    ) 