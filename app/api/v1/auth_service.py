from datetime import timedelta
from typing import Any, Dict, Optional
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, field_validator

from app.core.config import settings
from app.service.cognito.cognito_auth import CognitoAuthService
from app.service.cognito.cognito_verify import get_current_user

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter()
security = HTTPBearer()

# Initialize Cognito Auth Service
auth_service = CognitoAuthService()

# Existing models
class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: Optional[str] = None

class TokenData(BaseModel):
    username: str | None = None

class UserBase(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool = True

# New models for Cognito
class SignUpRequest(BaseModel):
    email: str
    password: str
    attributes: Optional[Dict] = None

class ConfirmSignUpRequest(BaseModel):
    email: str
    confirmation_code: str

class SignInRequest(BaseModel):
    email: str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ConfirmForgotPasswordRequest(BaseModel):
    email: str
    confirmation_code: str
    new_password: str

class ChangePasswordRequest(BaseModel):
    email: str
    old_password: str
    new_password: str

    @field_validator("new_password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def sign_up(request: SignUpRequest):
    """Register a new user with Cognito"""
    logger.info(f"Signup attempt for email: {request.email}")
    try:
        response = await auth_service.sign_up(request.email, request.password, request.attributes)
        if not response.success:
            logger.error(f"Signup failed for {request.email}: {response.message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=response.message
            )
        logger.info(f"Signup successful for {request.email}, UserSub: {response.data.get('userSub')}")
        return response
    except Exception as e:
        logger.error(f"Unexpected error during signup for {request.email}: {str(e)}")
        raise

@router.post("/confirm-signup", status_code=status.HTTP_200_OK)
async def confirm_sign_up(request: ConfirmSignUpRequest):
    """Confirm user registration with verification code"""
    logger.info(f"Confirmation attempt for email: {request.email}")
    try:
        response = await auth_service.confirm_sign_up(request.email, request.confirmation_code)
        if not response.success:
            logger.error(f"Confirmation failed for {request.email}: {response.message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=response.message
            )
        logger.info(f"Confirmation successful for {request.email}")
        return response
    except Exception as e:
        logger.error(f"Unexpected error during confirmation for {request.email}: {str(e)}")
        raise

@router.post("/resend-confirmation", status_code=status.HTTP_200_OK)
async def resend_confirmation_code(email: str):
    """Resend confirmation code to user's email"""
    response = await auth_service.resend_confirmation_code(email)
    if not response.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=response.message
        )
    return response

@router.post("/signin", response_model=Token)
async def sign_in(request: SignInRequest):
    """Sign in user and get tokens"""
    logger.info(f"Signin attempt for email: {request.email}")
    try:
        response = await auth_service.sign_in(request.email, request.password)
        if not response.success:
            logger.error(f"Signin failed for {request.email}: {response.message}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=response.message,
                headers={"WWW-Authenticate": "Bearer"},
            )
        logger.info(f"Signin successful for {request.email}")
        return {
            "access_token": response.data['AccessToken'],
            "refresh_token": response.data['RefreshToken'],
            "token_type": "bearer"
        }
    except Exception as e:
        logger.error(f"Unexpected error during signin for {request.email}: {str(e)}")
        raise

@router.post("/refresh-token", response_model=Token)
async def refresh_token(refresh_token: str):
    """Refresh access token using refresh token"""
    response = await auth_service.refresh_token(refresh_token)
    if not response.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=response.message
        )
    return {
        "access_token": response.data['access_token'],
        "refresh_token": response.data['refresh_token'],
        "token_type": "bearer"
    }

@router.post("/signout")
async def sign_out(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Sign out user by revoking tokens"""
    response = await auth_service.sign_out(current_user['access_token'])
    if not response.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=response.message
        )
    return response

@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    """Initiate forgot password flow"""
    logger.info(f"Forgot password attempt for email: {request.email}")
    try:
        response = await auth_service.forgot_password(request.email)
        if not response.success:
            logger.error(f"Forgot password failed for {request.email}: {response.message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=response.message
            )
        logger.info(f"Forgot password initiated successfully for {request.email}")
        return response
    except Exception as e:
        logger.error(f"Unexpected error during forgot password for {request.email}: {str(e)}")
        raise

@router.post("/confirm-forgot-password")
async def confirm_forgot_password(request: ConfirmForgotPasswordRequest):
    """Complete forgot password flow"""
    logger.info(f"Confirm forgot password attempt for email: {request.email}")
    try:
        response = await auth_service.confirm_forgot_password(
            request.email,
            request.confirmation_code,
            request.new_password
        )
        if not response.success:
            logger.error(f"Confirm forgot password failed for {request.email}: {response.message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=response.message
            )
        logger.info(f"Password reset successful for {request.email}")
        return response
    except Exception as e:
        logger.error(f"Unexpected error during confirm forgot password for {request.email}: {str(e)}")
        raise

@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    token: str = Depends(security)
):
    """Change user's password with token verification"""
    logger.info(f"Password change attempt for email: {request.email}")
    try:
        # First verify the token
        user = await get_current_user(token)
        if user.get('email') != request.email:
            logger.error(f"Email mismatch for password change. Token email: {user.get('email')}, Request email: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email does not match the authenticated user"
            )

        # Proceed with password change
        response = await auth_service.change_password(
            token,
            request.old_password,
            request.new_password
        )
        if not response.success:
            logger.error(f"Password change failed for {request.email}: {response.message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=response.message
            )
        logger.info(f"Password change successful for {request.email}")
        return response
    except Exception as e:
        logger.error(f"Unexpected error during password change for {request.email}: {str(e)}")
        raise

@router.get("/user-attributes")
async def get_user_attributes(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get user attributes"""
    logger.info(f"Fetching user attributes for email: {current_user.get('email')}")
    try:
        response = await auth_service.get_user_attributes(current_user['access_token'])
        if not response.success:
            logger.error(f"Failed to fetch user attributes for {current_user.get('email')}: {response.message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=response.message
            )
        logger.info(f"Successfully fetched user attributes for {current_user.get('email')}")
        return response
    except Exception as e:
        logger.error(f"Unexpected error fetching user attributes for {current_user.get('email')}: {str(e)}")
        raise 