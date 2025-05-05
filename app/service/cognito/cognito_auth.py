import os
import aiohttp
import base64
import hmac
import hashlib
import logging
from typing import Dict, Optional, Tuple, Any, Union
from botocore.exceptions import ClientError

from jose.exceptions import JWTError
from pydantic import BaseModel, Field
from aioboto3 import Session
from app.core.config import settings

# Configure logging
logger = logging.getLogger(__name__)

class CognitoConfig(BaseModel):
    """Configuration model for Cognito settings"""
    user_pool_id: str = Field(..., description="Cognito User Pool ID")
    client_id: str = Field(..., description="Cognito Client ID")
    client_secret: Optional[str] = Field(None, description="Cognito Client Secret")
    region: str = Field(..., description="AWS Region")
    token_expiry: int = Field(3600, description="Token expiry in seconds")
    refresh_token_expiry: int = Field(30 * 24 * 3600, description="Refresh token expiry in seconds")

class AuthResponse(BaseModel):
    """Response model for authentication operations"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class UserAttributes(BaseModel):
    """Model for user attributes"""
    email: Optional[str] = None
    name: Optional[str] = None
    phone_number: Optional[str] = None
    custom_attributes: Optional[Dict[str, str]] = None

class CognitoAuthService:
    def __init__(self):
        logger.info("Initializing AuthService")
        cognito_config = settings.get_cognito_config()
        self.config = CognitoConfig(
            user_pool_id=cognito_config["user_pool_id"],
            client_id=cognito_config["client_id"],
            client_secret=cognito_config["client_secret"],
            region=cognito_config["region"]
        )
        self.session = Session()
        logger.info(f"AuthService initialized with User Pool ID: {self.config.user_pool_id}")

    def _compute_secret_hash(self, username: str) -> Optional[str]:
        """Compute the secret hash for Cognito API calls"""
        if not self.config.client_secret:
            return None
        try:
            message = username + self.config.client_id
            dig = hmac.new(
                self.config.client_secret.encode('UTF-8'),
                msg=message.encode('UTF-8'),
                digestmod=hashlib.sha256
            ).digest()
            return base64.b64encode(dig).decode()
        except Exception as e:
            logger.error(f"Error computing secret hash: {str(e)}")
            return None

    def _handle_cognito_error(self, error: ClientError) -> AuthResponse:
        """Handle Cognito API errors with detailed logging"""
        error_code = error.response['Error']['Code']
        error_message = error.response['Error']['Message']
        logger.error(f"Cognito error: {error_code} - {error_message}")
        
        if error_code == 'NotAuthorizedException':
            return AuthResponse(success=False, message='Invalid credentials')
        elif error_code == 'UserNotFoundException':
            return AuthResponse(success=False, message='User not found')
        elif error_code == 'UsernameExistsException':
            return AuthResponse(success=False, message='User already exists')
        elif error_code == 'InvalidParameterException':
            return AuthResponse(success=False, message=error_message)
        elif error_code == 'CodeMismatchException':
            return AuthResponse(success=False, message='Invalid verification code')
        elif error_code == 'ExpiredCodeException':
            return AuthResponse(success=False, message='Verification code has expired')
        else:
            return AuthResponse(success=False, message=f'AWS Cognito error: {error_message}')

    async def sign_up(self, email: str, password: str, attributes: Optional[Dict] = None) -> AuthResponse:
        """Register a new user in Cognito User Pool with enhanced error handling."""
        logger.info(f"Attempting to sign up user: {email}")
        try:
            sign_up_params = {
                'ClientId': self.config.client_id,
                'Username': email,
                'Password': password,
                'UserAttributes': [
                    {'Name': 'email', 'Value': email},
                ]
            }
            
            if secret_hash := self._compute_secret_hash(email):
                sign_up_params['SecretHash'] = secret_hash
            
            if attributes:
                logger.debug(f"Adding custom attributes for user {email}: {attributes}")
                for key, value in attributes.items():
                    sign_up_params['UserAttributes'].append({
                        'Name': key,
                        'Value': str(value)
                    })

            async with self.session.client('cognito-idp', region_name=self.config.region) as cognito:
                logger.debug(f"Calling Cognito sign_up API for user {email}")
                response = await cognito.sign_up(**sign_up_params)
            
            logger.info(f"Successfully signed up user {email} with UserSub: {response.get('UserSub')}")
            return AuthResponse(
                success=True,
                message='User registered successfully. Please check your email for verification code.',
                data={
                    'userSub': response.get('UserSub'),
                    'username': email,
                    'attributes': sign_up_params['UserAttributes']
                }
            )
        except ClientError as e:
            logger.error(f"Cognito sign_up error for {email}: {str(e)}")
            return self._handle_cognito_error(e)
        except Exception as e:
            logger.error(f"Unexpected error during sign up for {email}: {str(e)}")
            return AuthResponse(
                success=False,
                message='An unexpected error occurred',
                error=str(e)
            )

    async def confirm_sign_up(self, email: str, confirmation_code: str) -> AuthResponse:
        """Confirm user registration with enhanced error handling."""
        logger.info(f"Attempting to confirm sign up for user: {email}")
        try:
            confirm_params = {
                'ClientId': self.config.client_id,
                'Username': email,
                'ConfirmationCode': confirmation_code
            }
            
            if secret_hash := self._compute_secret_hash(email):
                confirm_params['SecretHash'] = secret_hash

            async with self.session.client('cognito-idp', region_name=self.config.region) as cognito:
                logger.debug(f"Calling Cognito confirm_sign_up API for user {email}")
                await cognito.confirm_sign_up(**confirm_params)
            
            logger.info(f"Successfully confirmed sign up for user {email}")
            return AuthResponse(
                success=True,
                message='User confirmed successfully'
            )
        except ClientError as e:
            logger.error(f"Cognito confirm_sign_up error for {email}: {str(e)}")
            return self._handle_cognito_error(e)
        except Exception as e:
            logger.error(f"Unexpected error during confirmation for {email}: {str(e)}")
            return AuthResponse(
                success=False,
                message='An unexpected error occurred',
                error=str(e)
            )

    async def sign_in(self, email: str, password: str) -> AuthResponse:
        """Sign in user with enhanced error handling."""
        logger.info(f"Attempting to sign in user: {email}")
        try:
            auth_params = {
                'ClientId': self.config.client_id,
                'AuthFlow': 'USER_PASSWORD_AUTH',
                'AuthParameters': {
                    'USERNAME': email,
                    'PASSWORD': password
                }
            }
            
            if secret_hash := self._compute_secret_hash(email):
                auth_params['AuthParameters']['SECRET_HASH'] = secret_hash

            async with self.session.client('cognito-idp', region_name=self.config.region) as cognito:
                logger.debug(f"Calling Cognito initiate_auth API for user {email}")
                response = await cognito.initiate_auth(**auth_params)
            
            logger.info(f"Successfully signed in user {email}")
            return AuthResponse(
                success=True,
                message='Sign in successful',
                data=response['AuthenticationResult']
            )
        except ClientError as e:
            logger.error(f"Cognito sign_in error for {email}: {str(e)}")
            return self._handle_cognito_error(e)
        except Exception as e:
            logger.error(f"Unexpected error during sign in for {email}: {str(e)}")
            return AuthResponse(
                success=False,
                message='An unexpected error occurred',
                error=str(e)
            )

    async def change_password(self, access_token: str, old_password: str, new_password: str) -> AuthResponse:
        """Change user's password with enhanced error handling."""
        logger.info("Attempting to change password")
        try:
            async with self.session.client('cognito-idp', region_name=self.config.region) as cognito:
                logger.debug("Calling Cognito change_password API")
                await cognito.change_password(
                    AccessToken=access_token,
                    OldPassword=old_password,
                    NewPassword=new_password
                )
            
            logger.info("Successfully changed password")
            return AuthResponse(
                success=True,
                message='Password changed successfully'
            )
        except ClientError as e:
            logger.error(f"Cognito change_password error: {str(e)}")
            return self._handle_cognito_error(e)
        except Exception as e:
            logger.error(f"Unexpected error during password change: {str(e)}")
            return AuthResponse(
                success=False,
                message='An unexpected error occurred',
                error=str(e)
            )

    async def forgot_password(self, email: str) -> AuthResponse:
        """Initiate forgot password flow with enhanced error handling."""
        logger.info(f"Attempting to initiate forgot password for user: {email}")
        try:
            forgot_params = {
                'ClientId': self.config.client_id,
                'Username': email
            }
            
            if secret_hash := self._compute_secret_hash(email):
                forgot_params['SecretHash'] = secret_hash

            async with self.session.client('cognito-idp', region_name=self.config.region) as cognito:
                logger.debug(f"Calling Cognito forgot_password API for user {email}")
                await cognito.forgot_password(**forgot_params)
            
            logger.info(f"Successfully initiated forgot password for user {email}")
            return AuthResponse(
                success=True,
                message='Verification code sent to your email'
            )
        except ClientError as e:
            logger.error(f"Cognito forgot_password error for {email}: {str(e)}")
            return self._handle_cognito_error(e)
        except Exception as e:
            logger.error(f"Unexpected error during forgot password for {email}: {str(e)}")
            return AuthResponse(
                success=False,
                message='An unexpected error occurred',
                error=str(e)
            )

    async def confirm_forgot_password(self, email: str, confirmation_code: str, new_password: str) -> AuthResponse:
        """Complete forgot password flow with enhanced error handling."""
        logger.info(f"Attempting to confirm forgot password for user: {email}")
        try:
            confirm_params = {
                'ClientId': self.config.client_id,
                'Username': email,
                'ConfirmationCode': confirmation_code,
                'Password': new_password
            }
            
            if secret_hash := self._compute_secret_hash(email):
                confirm_params['SecretHash'] = secret_hash

            async with self.session.client('cognito-idp', region_name=self.config.region) as cognito:
                logger.debug(f"Calling Cognito confirm_forgot_password API for user {email}")
                await cognito.confirm_forgot_password(**confirm_params)
            
            logger.info(f"Successfully confirmed forgot password for user {email}")
            return AuthResponse(
                success=True,
                message='Password has been reset successfully'
            )
        except ClientError as e:
            logger.error(f"Cognito confirm_forgot_password error for {email}: {str(e)}")
            return self._handle_cognito_error(e)
        except Exception as e:
            logger.error(f"Unexpected error during confirm forgot password for {email}: {str(e)}")
            return AuthResponse(
                success=False,
                message='An unexpected error occurred',
                error=str(e)
            )

    async def get_user_attributes(self, access_token: str) -> AuthResponse:
        """Get user attributes with enhanced error handling."""
        logger.info("Attempting to get user attributes")
        try:
            async with self.session.client('cognito-idp', region_name=self.config.region) as cognito:
                logger.debug("Calling Cognito get_user API")
                response = await cognito.get_user(AccessToken=access_token)
            
            logger.info("Successfully retrieved user attributes")
            return AuthResponse(
                success=True,
                message='User attributes retrieved successfully',
                data={
                    'username': response['Username'],
                    'attributes': {attr['Name']: attr['Value'] for attr in response['UserAttributes']}
                }
            )
        except ClientError as e:
            logger.error(f"Cognito get_user_attributes error: {str(e)}")
            return self._handle_cognito_error(e)
        except Exception as e:
            logger.error(f"Unexpected error getting user attributes: {str(e)}")
            return AuthResponse(
                success=False,
                message='An unexpected error occurred',
                error=str(e)
            )

    async def resend_confirmation_code(self, email: str) -> AuthResponse:
        """
        Resend confirmation code to user's email with enhanced error handling.
        
        Args:
            email: Email address of the user
            
        Returns:
            AuthResponse containing the response from Cognito
        """
        logger.info(f"Attempting to resend confirmation code for user: {email}")
        try:
            resend_params = {
                'ClientId': self.config.client_id,
                'Username': email
            }
            
            if secret_hash := self._compute_secret_hash(email):
                resend_params['SecretHash'] = secret_hash

            async with self.session.client('cognito-idp', region_name=self.config.region) as cognito:
                logger.debug(f"Calling Cognito resend_confirmation_code API for user {email}")
                response = await cognito.resend_confirmation_code(**resend_params)
            
            logger.info(f"Successfully resent confirmation code for user {email}")
            return AuthResponse(
                success=True,
                message='Confirmation code resent successfully',
                data=response
            )
        except ClientError as e:
            logger.error(f"Cognito resend_confirmation_code error for {email}: {str(e)}")
            return self._handle_cognito_error(e)
        except Exception as e:
            logger.error(f"Unexpected error during resend confirmation code for {email}: {str(e)}")
            return AuthResponse(
                success=False,
                message='An unexpected error occurred',
                error=str(e)
            )

    async def sign_out(self, access_token: str) -> AuthResponse:
        """
        Sign out a user by revoking their tokens with enhanced error handling.
        
        Args:
            access_token: Access token of the user
            
        Returns:
            AuthResponse containing the response from Cognito
        """
        logger.info("Attempting to sign out user")
        try:
            async with self.session.client('cognito-idp', region_name=self.config.region) as cognito:
                logger.debug("Calling Cognito global_sign_out API")
                response = await cognito.global_sign_out(
                    AccessToken=access_token
                )
            
            logger.info("Successfully signed out user")
            return AuthResponse(
                success=True,
                message='User signed out successfully',
                data=response
            )
        except ClientError as e:
            logger.error(f"Cognito sign_out error: {str(e)}")
            return self._handle_cognito_error(e)
        except Exception as e:
            logger.error(f"Unexpected error during sign out: {str(e)}")
            return AuthResponse(
                success=False,
                message='An unexpected error occurred',
                error=str(e)
            )

    async def refresh_token(self, refresh_token: str) -> AuthResponse:
        """Refresh access token using refresh token with enhanced error handling."""
        logger.info("Attempting to refresh token")
        try:
            token_endpoint = "https://us-west-2oy5e6oom4.auth.us-west-2.amazoncognito.com/oauth2/token"
            
            auth_str = f"{self.config.client_id}:{self.config.client_secret}"
            b64_auth = base64.b64encode(auth_str.encode()).decode()
            
            headers = {
                "Authorization": f"Basic {b64_auth}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.config.client_id
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(token_endpoint, headers=headers, data=data) as response:
                    if response.status == 200:
                        response_data = await response.json()
                        logger.info("Successfully refreshed token")
                        return AuthResponse(
                            success=True,
                            message='Tokens refreshed successfully',
                            data=response_data
                        )
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to refresh token: {response.status} - {error_text}")
                        return AuthResponse(
                            success=False,
                            message=f'Failed to refresh token: {response.status}',
                            error=error_text
                        )
        except Exception as e:
            logger.error(f"Unexpected error during token refresh: {str(e)}")
            return AuthResponse(
                success=False,
                message='An unexpected error occurred during token refresh',
                error=str(e)
            )

