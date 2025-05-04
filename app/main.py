from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes import api_router
from app.core.health import health_router
from app.startup import startup_db_handler, shutdown_db_handler

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
)

# Set all CORS enabled origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register startup and shutdown events
@app.on_event("startup")
async def startup_event():
    await startup_db_handler()

@app.on_event("shutdown")
async def shutdown_event():
    await shutdown_db_handler()

# Include routers
app.include_router(health_router, tags=["health"])
app.include_router(api_router, prefix=settings.API_V1_STR) 