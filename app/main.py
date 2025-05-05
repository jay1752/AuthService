from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import time
import uuid
from typing import Any, Dict

from app.core.config import settings
from app.api.routes import api_router
from app.core.health import health_router
from app.api.v1.auth_service import router as auth_router
from app.service.cognito.cognito_verify import token_verifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
from app.startup import startup_db_handler, shutdown_db_handler

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    logger.info(f"Request started: {request.method} {request.url.path}")
    
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        logger.info(f"Request completed: {request.method} {request.url.path} - Status: {response.status_code} - Time: {process_time:.2f}s")
        return response
    except Exception as e:
        logger.error(f"Request failed: {request.method} {request.url.path} - Error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "code": exc.status_code,
            "path": request.url.path,
            "correlation_id": getattr(request.state, "correlation_id", None)
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        f"Unhandled exception: {str(exc)}",
        extra={"correlation_id": getattr(request.state, "correlation_id", None)}
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "path": request.url.path,
            "correlation_id": getattr(request.state, "correlation_id", None)
        }
    )

# Include routers
app.include_router(health_router, tags=["health"])
app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(auth_router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])

@app.on_event("startup")
async def startup_event():
    logger.info("Starting up Auth Service")
    try:
        await token_verifier.initialize()
        logger.info("Token verifier initialized successfully")
        await startup_db_handler()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize token verifier: {str(e)}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    await shutdown_db_handler()
    logger.info("Shutting down Auth Service")
