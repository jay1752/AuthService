import os
import secrets
from typing import List

from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )
    
    # API Settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Auth Service"
    VERSION: str = "0.1.0"
    DESCRIPTION: str = "Authentication and Authorization Service API"
    
    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]

    @field_validator("CORS_ORIGINS")
    def assemble_cors_origins(cls, v: List[str]) -> List[str] | str:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, list):
            return v
        raise ValueError(v)
    
    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "dev")
    
    # Log level
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # AWS Cognito Settings
    COGNITO_USER_POOL_ID: str = os.getenv("COGNITO_USER_POOL_ID", "")
    COGNITO_CLIENT_ID: str = os.getenv("COGNITO_CLIENT_ID", "")
    COGNITO_CLIENT_SECRET: str = os.getenv("COGNITO_CLIENT_SECRET", "")
    COGNITO_REGION: str = os.getenv("COGNITO_REGION", "us-east-1")

    def get_cognito_config(self) -> dict:
        """Get Cognito configuration as a dictionary."""
        return {
            "user_pool_id": self.COGNITO_USER_POOL_ID,
            "client_id": self.COGNITO_CLIENT_ID,
            "client_secret": self.COGNITO_CLIENT_SECRET,
            "region": self.COGNITO_REGION
        }


settings = Settings() 