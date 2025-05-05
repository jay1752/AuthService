from fastapi import APIRouter, status, Request
from pydantic import BaseModel
from app.core.config import settings
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
async def health_check(request: Request):
    """
    Health check endpoint which returns status, version and environment.
    Used by Kubernetes probes and monitoring systems.
    """
    logger.info(f"Health check request from {request.client.host}")
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
async def readiness(request: Request):
    """
    Readiness probe endpoint which returns status, version and environment.
    Used by Kubernetes readiness probes.
    """
    logger.info(f"Readiness check request from {request.client.host}")
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
async def liveness(request: Request):
    """
    Liveness probe endpoint which returns status, version and environment.
    Used by Kubernetes liveness probes.
    """
    logger.info(f"Liveness check request from {request.client.host}")
    return HealthResponse(
        status="alive",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT
    ) 